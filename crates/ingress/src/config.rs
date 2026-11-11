use crate::{Source, Workload};

/// The callers an [`Ingress`](crate::Ingress) holds at once unless
/// [`connection_limit`](IngressConfig::connection_limit) says otherwise.
const DEFAULT_CONNECTION_LIMIT: usize = 1024;

/// What an [`Ingress`](crate::Ingress) relays: callers from a source, to the workload.
#[derive(Debug)]
pub struct IngressConfig {
    pub(crate) source: Source,
    pub(crate) workload: Workload,
    pub(crate) connection_limit: usize,
}

impl IngressConfig {
    /// Relay each caller from `source` to `workload`.
    pub fn new(source: Source, workload: Workload) -> Self {
        Self {
            source,
            workload,
            connection_limit: DEFAULT_CONNECTION_LIMIT,
        }
    }

    /// Hold at most `limit` callers at once. A further caller waits in the source's queue until one
    /// closes.
    pub fn connection_limit(mut self, limit: usize) -> Self {
        self.connection_limit = limit.max(1);
        self
    }
}
