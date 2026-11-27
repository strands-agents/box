//! A credsd access token that the vault reads again near its expiry, off the request path while the
//! held token is still valid.
//!
//! | Held token | A request |
//! | --- | --- |
//! | Valid, before its refresh deadline | Attaches it. |
//! | Valid, past its refresh deadline | Attaches it, and starts one background read when no read is running or waiting to retry. |
//! | Expired, or none | Waits for the running read, or starts one; refused while a failed read waits to retry. |

use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use crate::sources::{CREDSD_SCHEME, CredsdClient, GetFailure, credsd_access_token_class};
use crate::{CredentialError, RequestId, Secret};

/// The wait after a first failed read before the next one; each further failure doubles it.
const REFRESH_RETRY: Duration = Duration::from_secs(1);

/// The longest wait between two failed reads.
const REFRESH_RETRY_MAX: Duration = Duration::from_secs(30);

/// The latest a refresh deadline falls before expiry.
const REFRESH_MARGIN_MAX: Duration = Duration::from_secs(60);

/// The correlation id a refresh read uses for its audit record.
const REFRESH_CORRELATION: &str = "credential-store-refresh";

/// One instant on both the monotonic and the wall clock.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Moment {
    monotonic: Instant,
    wall: SystemTime,
}

impl Moment {
    fn after(self, wait: Duration) -> Deadline {
        Deadline {
            monotonic: self.monotonic + wait,
            wall: self.wall + wait,
        }
    }
}

/// A deadline that passes when either clock reaches it: the monotonic clock ignores a wall-clock
/// step, and the wall clock keeps counting while the host sleeps.
#[derive(Clone, Copy, Debug)]
struct Deadline {
    monotonic: Instant,
    wall: SystemTime,
}

impl Deadline {
    fn passed(&self, now: Moment) -> bool {
        now.monotonic >= self.monotonic || now.wall >= self.wall
    }

    fn earlier(self, other: Self) -> Self {
        Self {
            monotonic: self.monotonic.min(other.monotonic),
            wall: self.wall.min(other.wall),
        }
    }
}

/// The time source a token reads its deadlines against.
#[derive(Clone, Debug)]
pub(crate) enum Clock {
    System,
    #[cfg(test)]
    Manual(Arc<Mutex<Moment>>),
}

impl Clock {
    /// The system clock, or the test clock installed on this thread.
    pub(crate) fn current() -> Self {
        #[cfg(test)]
        if let Some(clock) = tests::TEST_CLOCK.with(|clock| clock.borrow().clone()) {
            return Self::Manual(clock);
        }
        Self::System
    }

    pub(crate) fn now(&self) -> Moment {
        match self {
            Self::System => Moment {
                monotonic: Instant::now(),
                wall: SystemTime::now(),
            },
            #[cfg(test)]
            Self::Manual(moment) => *moment.lock().unwrap(),
        }
    }
}

/// Why a token read failed, carrying no daemon-supplied text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TokenFailure {
    /// The daemon read failed, with its class and its operator-facing reason.
    Get(GetFailure, String),
    NoExpiry,
    InvalidExpiry,
    Expired,
}

impl TokenFailure {
    fn get(class: GetFailure, error: &CredentialError) -> Self {
        Self::Get(class, error.detail().to_owned())
    }

    /// The operator-facing reason, which names the credential and nothing the daemon wrote.
    pub(crate) fn message(&self, credential: &str) -> String {
        match self {
            Self::Get(_, message) => message.clone(),
            Self::NoExpiry => {
                format!("credsd returned no expires_at for credential {credential:?}")
            }
            Self::InvalidExpiry => {
                format!("credsd credential {credential:?} has an invalid expires_at")
            }
            Self::Expired => {
                format!("credsd returned an expired token for credential {credential:?}")
            }
        }
    }
}

/// One token read: the secret and the deadlines it carries.
pub(crate) struct CachedToken {
    secret: Arc<Secret>,
    refresh: Deadline,
    expiry: Deadline,
}

impl CachedToken {
    /// Fix the daemon's RFC 3339 `expires_at` on both clocks at `now`, the moment of the read.
    pub(crate) fn new(secret: Secret, expires_at: &str, now: Moment) -> Result<Self, TokenFailure> {
        let expiry: SystemTime = chrono::DateTime::parse_from_rfc3339(expires_at)
            .map_err(|_| TokenFailure::InvalidExpiry)?
            .into();
        let remaining = expiry
            .duration_since(now.wall)
            .ok()
            .filter(|remaining| !remaining.is_zero())
            .ok_or(TokenFailure::Expired)?;
        Ok(Self {
            secret: Arc::new(secret),
            refresh: now.after(remaining - refresh_margin(remaining)),
            expiry: now.after(remaining),
        })
    }
}

/// How long before expiry a token is read again: the last fifth of its lifetime, at most a minute.
fn refresh_margin(remaining: Duration) -> Duration {
    (remaining / 5).min(REFRESH_MARGIN_MAX)
}

/// Where a token is read from, and where each read is audited and reported.
pub(crate) struct TokenSource {
    pub(crate) credential: String,
    pub(crate) socket: PathBuf,
    pub(crate) tenant: String,
    pub(crate) emitter: Arc<dyn crate::Emitter>,
    pub(crate) clock: Clock,
}

impl TokenSource {
    /// Read the current token from the daemon, auditing the attempt.
    fn read(&self) -> Result<CachedToken, TokenFailure> {
        let mut failure = None;
        let read = crate::audit_resolve(
            self.emitter.as_ref(),
            &self.tenant,
            CREDSD_SCHEME,
            &format!("{CREDSD_SCHEME}://{}", self.credential),
            &RequestId::new(REFRESH_CORRELATION),
            || {
                let client = CredsdClient::new(self.socket.clone());
                credsd_access_token_class(&client, &self.credential)
                    .map_err(|(class, error)| TokenFailure::get(class, &error))
                    .and_then(|token| {
                        let expiry = token.expires_at.ok_or(TokenFailure::NoExpiry)?;
                        CachedToken::new(token.token, &expiry, self.clock.now())
                    })
                    .map_err(|cause| {
                        let error = CredentialError::Credential(cause.message(&self.credential));
                        failure = Some(cause);
                        error
                    })
            },
        );
        read.map_err(|error| {
            failure.unwrap_or_else(|| TokenFailure::get(GetFailure::Other, &error))
        })
    }

    fn stopped(&self, what: &str) -> TokenFailure {
        TokenFailure::Get(
            GetFailure::Other,
            format!("{what} for credsd credential {:?}", self.credential),
        )
    }

    /// [`read`](Self::read), with a panic counted as a failed read so no read stays running.
    fn read_guarded(&self) -> Result<CachedToken, TokenFailure> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.read()))
            .unwrap_or_else(|_| Err(self.stopped("the token read stopped unexpectedly")))
    }

    fn report(&self, message: &str) {
        #[cfg(test)]
        if let Some(before) = tests::BEFORE_REPORT.take() {
            before();
        }
        crate::vault::warn_operator(&self.tenant, message);
    }
}

/// A credsd token that every route naming it shares, with at most one read running.
pub(crate) struct RotatingToken {
    source: TokenSource,
    state: Mutex<TokenState>,
    settled: Condvar,
}

struct TokenState {
    current: Option<CachedToken>,
    refreshing: bool,
    /// Completed reads, so a waiter knows when the read it waited on settles.
    attempts: u64,
    failure: Option<TokenFailure>,
    retry: Option<Deadline>,
    backoff: Duration,
    reauth_reported: bool,
}

impl TokenState {
    fn may_read(&self, now: Moment) -> bool {
        !self.refreshing && self.retry.is_none_or(|retry| retry.passed(now))
    }

    fn valid(&self, now: Moment) -> Option<&CachedToken> {
        self.current
            .as_ref()
            .filter(|token| !token.expiry.passed(now))
    }
}

impl RotatingToken {
    pub(crate) fn new(source: TokenSource, first: CachedToken) -> Arc<Self> {
        Arc::new(Self {
            source,
            state: Mutex::new(TokenState {
                current: Some(first),
                refreshing: false,
                attempts: 0,
                failure: None,
                retry: None,
                backoff: REFRESH_RETRY,
                reauth_reported: false,
            }),
            settled: Condvar::new(),
        })
    }

    /// The token to attach, refused only when no valid token is held and none can be read now.
    pub(crate) fn acquire(self: &Arc<Self>) -> crate::Result<Arc<Secret>> {
        let mut state = self.lock();
        let now = self.source.clock.now();
        if let Some(token) = state.valid(now) {
            let secret = Arc::clone(&token.secret);
            if token.refresh.passed(now) && state.may_read(now) {
                state.refreshing = true;
                drop(state);
                self.refresh_in_background();
            }
            return Ok(secret);
        }
        if state.refreshing {
            // Share the running read's outcome, whichever request started it.
            let attempt = state.attempts;
            state = self
                .settled
                .wait_while(state, |state| state.attempts == attempt)
                .unwrap_or_else(PoisonError::into_inner);
        } else if state.may_read(now) {
            state.refreshing = true;
            drop(state);
            let read = self.source.read_guarded();
            state = self.settle(read);
        }
        match state.valid(self.source.clock.now()) {
            Some(token) => Ok(Arc::clone(&token.secret)),
            None => Err(self.refusal(&state)),
        }
    }

    fn refresh_in_background(self: &Arc<Self>) {
        let token = Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name("credsd-refresh".into())
            .spawn(move || {
                let read = token.source.read_guarded();
                drop(token.settle(read));
            });
        if spawned.is_err() {
            drop(self.settle(Err(self.source.stopped("Box could not start a token read"))));
        }
    }

    /// Record a read's outcome, wake every request waiting on it, and report a new re-authentication
    /// failure after releasing the lock, so a blocked stderr cannot stall requests.
    fn settle(&self, read: Result<CachedToken, TokenFailure>) -> MutexGuard<'_, TokenState> {
        let mut state = self.lock();
        let mut report = None;
        state.refreshing = false;
        state.attempts += 1;
        let now = self.source.clock.now();
        match read {
            Ok(next) => {
                state.current = Some(next);
                state.failure = None;
                state.retry = None;
                state.backoff = REFRESH_RETRY;
                state.reauth_reported = false;
            }
            Err(failure) => {
                let mut retry = now.after(state.backoff);
                match state.valid(now) {
                    // The next read is due no later than expiry, when the request path needs it.
                    Some(token) => retry = retry.earlier(token.expiry),
                    None => state.current = None,
                }
                state.retry = Some(retry);
                state.backoff = (state.backoff * 2).min(REFRESH_RETRY_MAX);
                if matches!(failure, TokenFailure::Get(GetFailure::ReauthRequired, _))
                    && !state.reauth_reported
                {
                    state.reauth_reported = true;
                    report = Some(format!(
                        "{}; once the held token expires, requests that need it are refused until a \
                         read succeeds",
                        failure.message(&self.source.credential)
                    ));
                }
                state.failure = Some(failure);
            }
        }
        self.settled.notify_all();
        match report {
            Some(message) => {
                drop(state);
                self.source.report(&message);
                self.lock()
            }
            None => state,
        }
    }

    fn refusal(&self, state: &TokenState) -> CredentialError {
        let credential = &self.source.credential;
        CredentialError::Credential(match &state.failure {
            Some(failure) => format!("credsd refresh failed: {}", failure.message(credential)),
            None => format!("credsd holds no valid token for credential {credential:?}"),
        })
    }

    fn lock(&self) -> MutexGuard<'_, TokenState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Wait until no read is running.
    #[cfg(test)]
    pub(crate) fn wait_settled(&self) {
        drop(
            self.settled
                .wait_while(self.lock(), |state| state.refreshing)
                .unwrap_or_else(PoisonError::into_inner),
        );
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::cell::RefCell;

    use super::*;

    thread_local! {
        pub(super) static TEST_CLOCK: RefCell<Option<Arc<Mutex<Moment>>>> =
            const { RefCell::new(None) };
        /// Run on this thread before a token reports to the operator.
        pub(crate) static BEFORE_REPORT: RefCell<Option<Box<dyn FnOnce()>>> =
            const { RefCell::new(None) };
    }

    /// A clock a test moves by hand, installed for every token opened on this thread.
    pub(crate) struct ManualClock {
        moment: Arc<Mutex<Moment>>,
        base: Instant,
    }

    impl ManualClock {
        /// Install a clock that reads the Unix epoch on both clocks.
        pub(crate) fn install() -> Self {
            let base = Instant::now();
            let moment = Arc::new(Mutex::new(Moment {
                monotonic: base,
                wall: SystemTime::UNIX_EPOCH,
            }));
            TEST_CLOCK.with(|clock| *clock.borrow_mut() = Some(Arc::clone(&moment)));
            Self { moment, base }
        }

        /// Move both clocks to `seconds` after the epoch.
        pub(crate) fn set(&self, seconds: u64) {
            self.set_split(seconds, seconds);
        }

        /// Move the monotonic clock and the wall clock to two different offsets from the epoch.
        pub(crate) fn set_split(&self, monotonic: u64, wall: u64) {
            *self.moment.lock().unwrap() = Moment {
                monotonic: self.base + Duration::from_secs(monotonic),
                wall: SystemTime::UNIX_EPOCH + Duration::from_secs(wall),
            };
        }
    }

    impl Drop for ManualClock {
        fn drop(&mut self) {
            TEST_CLOCK.with(|clock| *clock.borrow_mut() = None);
        }
    }

    fn epoch(seconds: u64) -> Moment {
        Moment {
            monotonic: Instant::now(),
            wall: SystemTime::UNIX_EPOCH + Duration::from_secs(seconds),
        }
    }

    fn secret() -> Secret {
        Secret::new(zeroize::Zeroizing::new("token".into()), "credsd://t").unwrap()
    }

    #[test]
    fn refresh_window_scales_with_lifetime_and_does_not_extend_expiry() {
        let refresh_wall = |now: u64, expires_at: &str| {
            CachedToken::new(secret(), expires_at, epoch(now)).map(|token| token.refresh.wall)
        };
        let at = |seconds| SystemTime::UNIX_EPOCH + Duration::from_secs(seconds);
        let expiry = "1970-01-01T01:00:00Z";
        for seconds in [0, 3540] {
            let now = epoch(seconds);
            let token = CachedToken::new(secret(), expiry, now).unwrap();
            assert_eq!(
                token.expiry.wall,
                at(3600),
                "expiry stays where the daemon put it"
            );
            assert_eq!(
                token.expiry.monotonic,
                now.monotonic + Duration::from_secs(3600 - seconds),
                "the monotonic expiry matches the wall expiry"
            );
        }
        assert_eq!(refresh_wall(0, expiry).unwrap(), at(3540));
        // A daemon may still return the same credential in the early refresh window.
        assert_eq!(refresh_wall(3540, expiry).unwrap(), at(3588));
        assert_eq!(
            refresh_wall(3600, expiry).err(),
            Some(TokenFailure::Expired)
        );
        assert_eq!(
            refresh_wall(3601, expiry).err(),
            Some(TokenFailure::Expired)
        );
        assert_eq!(
            refresh_wall(0, "1970-01-01T01:00:00.500+01:00").unwrap(),
            at(0) + Duration::from_millis(400)
        );
        assert_eq!(
            refresh_wall(0, "not-a-time").err(),
            Some(TokenFailure::InvalidExpiry)
        );
    }

    /// Each deadline passes on whichever clock reaches it first, so neither a wall-clock step back
    /// nor a host sleep that stops the monotonic clock keeps an expired token in use.
    #[test]
    fn a_deadline_passes_on_either_clock() {
        let start = Moment {
            monotonic: Instant::now(),
            wall: SystemTime::UNIX_EPOCH,
        };
        let deadline = start.after(Duration::from_secs(60));
        let at = |monotonic: u64, wall: u64| Moment {
            monotonic: start.monotonic + Duration::from_secs(monotonic),
            wall: SystemTime::UNIX_EPOCH + Duration::from_secs(wall),
        };
        assert!(!deadline.passed(at(59, 59)));
        assert!(deadline.passed(at(60, 0)), "the wall clock stepped back");
        assert!(deadline.passed(at(0, 60)), "the host slept");
    }
}
