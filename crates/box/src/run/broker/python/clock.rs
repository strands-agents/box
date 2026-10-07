//! The clock and entropy a Monty script reads, answered from the host in UTC.

use std::fs::File;
use std::io::Read as _;
use std::time::{SystemTime, UNIX_EPOCH};

use monty_types::{ExcType, MontyDate, MontyDateTime, MontyException, MontyObject, MontyTimeZone};

use super::effects::io_exception;

/// Bound on the bytes of one `os.urandom` call.
const URANDOM_LIMIT: u64 = 1024 * 1024;

/// `os.urandom(size)`, read from the host's entropy source.
pub(super) fn urandom(size: u64) -> Result<MontyObject, MontyException> {
    if size > URANDOM_LIMIT {
        return Err(MontyException::new(
            ExcType::ValueError,
            Some(format!(
                "os.urandom: at most {URANDOM_LIMIT} bytes per call in this box"
            )),
        ));
    }
    let mut bytes = vec![0; usize::try_from(size).unwrap_or(0)];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|error| io_exception(&error))?;
    Ok(MontyObject::bytes(bytes))
}

/// The current instant as `(unix seconds, microseconds)`, clamped to the epoch if the clock is
/// somehow before it, so a broken clock cannot panic the interpreter.
fn unix_now() -> (i64, u32) {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => (elapsed.as_secs() as i64, elapsed.subsec_micros()),
        Err(_) => (0, 0),
    }
}

/// Split a unix-epoch second count into UTC civil fields, by Howard Hinnant's `civil_from_days`.
fn civil_from_unix(secs: i64) -> (i32, u8, u8, u8, u8, u8) {
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let hour = (tod / 3_600) as u8;
    let minute = ((tod % 3_600) / 60) as u8;
    let second = (tod % 60) as u8;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u8; // [1, 31]
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u8; // [1, 12]
    let year = (yoe + era * 400 + i64::from(month <= 2)) as i32;
    (year, month, day, hour, minute, second)
}

/// `time.time()` — seconds since the Unix epoch.
pub(super) fn unix_seconds_now() -> f64 {
    let (secs, microsecond) = unix_now();
    secs as f64 + f64::from(microsecond) / 1_000_000.0
}

/// `date.today()` — the current UTC date.
pub(super) fn date_today() -> MontyDate {
    let (year, month, day, ..) = civil_from_unix(unix_now().0);
    MontyDate { year, month, day }
}

/// `datetime.now(tz)`. With no zone it is a naive UTC value; with a zone it is that instant shifted
/// into the zone and marked aware.
pub(super) fn datetime_now(zone: Option<&MontyTimeZone>) -> MontyDateTime {
    let (secs, microsecond) = unix_now();
    datetime_from(secs, microsecond, zone)
}

/// Build a `MontyDateTime` from a fixed instant, so the zone shift and awareness are testable
/// without the live clock.
fn datetime_from(secs: i64, microsecond: u32, zone: Option<&MontyTimeZone>) -> MontyDateTime {
    let offset_seconds = zone.map(|zone| zone.offset_seconds);
    let timezone_name = zone.and_then(|zone| zone.name.clone());
    let (year, month, day, hour, minute, second) =
        civil_from_unix(secs + i64::from(offset_seconds.unwrap_or(0)));
    MontyDateTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
        microsecond,
        offset_seconds,
        timezone_name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::run::broker::python::tests::{permissive, run_script};
    use crate::test_support::open_policy;

    #[test]
    fn civil_from_unix_maps_known_instants() {
        assert_eq!(civil_from_unix(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(civil_from_unix(1_709_164_800), (2024, 2, 29, 0, 0, 0)); // a leap day
        assert_eq!(civil_from_unix(1_700_000_000), (2023, 11, 14, 22, 13, 20));
    }

    #[test]
    fn datetime_from_naive_is_utc_with_no_offset() {
        let dt = datetime_from(1_700_000_000, 500_000, None);
        assert_eq!(
            (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second),
            (2023, 11, 14, 22, 13, 20)
        );
        assert_eq!(dt.microsecond, 500_000);
        assert_eq!(dt.offset_seconds, None);
        assert_eq!(dt.timezone_name, None);
    }

    #[test]
    fn datetime_from_with_a_zone_shifts_and_marks_aware() {
        let zone = MontyTimeZone {
            offset_seconds: 3_600,
            name: Some("UTC+1".to_string()),
        };
        let dt = datetime_from(1_700_000_000, 0, Some(&zone));
        assert_eq!(dt.hour, 23); // 22:13:20 UTC + 1h
        assert_eq!((dt.year, dt.month, dt.day), (2023, 11, 14));
        assert_eq!(dt.offset_seconds, Some(3_600));
        assert_eq!(dt.timezone_name.as_deref(), Some("UTC+1"));
    }

    #[test]
    fn date_today_is_a_valid_calendar_date() {
        let today = date_today();
        assert!(
            today.year >= 2024,
            "the clock should be past 2024: {}",
            today.year
        );
        assert!((1..=12).contains(&today.month));
        assert!((1..=31).contains(&today.day));
    }

    #[tokio::test]
    async fn the_clock_and_entropy_are_answered_without_a_policy_decision() {
        let outcome = run_script(
            "import os, time\nprint(time.time() > 0, time.monotonic() >= 0, len(os.urandom(16)))",
            &open_policy(Vec::new()),
        )
        .await;
        assert_eq!(outcome.status, 0, "{}", outcome.stderr);
        assert_eq!(outcome.stdout.trim(), "True True 16");
    }

    #[tokio::test]
    async fn urandom_above_its_cap_is_a_catchable_python_error() {
        let outcome = run_script(
            &format!(
                "import os\ntry:\n    os.urandom({})\nexcept ValueError:\n    print('refused')\nprint(len(os.urandom({URANDOM_LIMIT})))",
                URANDOM_LIMIT + 1
            ),
            &permissive(),
        )
        .await;
        assert_eq!(outcome.status, 0, "{}", outcome.stderr);
        assert_eq!(outcome.stdout, format!("refused\n{URANDOM_LIMIT}\n"));
    }
}
