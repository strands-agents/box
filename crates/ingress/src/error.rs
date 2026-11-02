/// The ingress relay could not start.
#[derive(Debug, thiserror::Error)]
pub enum IngressError {
    /// The source or the workload could not be prepared.
    #[error("preparing the ingress relay: {0}")]
    Prepare(#[from] std::io::Error),
}
