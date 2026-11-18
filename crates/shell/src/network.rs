use std::io;

use async_trait::async_trait;
use strands_shell::os::{HttpRequest, HttpResponse};

/// Sends the Shell's HTTP requests, after the SSRF floor.
#[async_trait]
pub trait Network: Send + Sync {
    /// Send one request and return its response, or the refusal.
    async fn send(&self, request: HttpRequest) -> io::Result<HttpResponse>;
}
