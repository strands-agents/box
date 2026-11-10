/// The ingress relay could not start.
#[derive(Debug, thiserror::Error)]
pub enum IngressError {
    /// The source or the workload could not be prepared.
    #[error("preparing the ingress relay: {0}")]
    Prepare(#[from] std::io::Error),
    /// The namespace's PID 1 closed the channel, or sent something other than ready.
    #[error("the sandbox did not report that it is ready to take callers")]
    NotReady,
}
