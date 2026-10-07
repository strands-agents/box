//! The two decisions an MCP server meets: may it run, and may this request be made.
//!
//! | Module | Part |
//! |---|---|
//! | `admission` | the `shell:spawn` start and the `mcp:call` decision on each request |
//! | `discovery` | the stdio servers' share of the box's tool catalogs |
//! | `exchange` | one client connection, relayed frame by frame |
//! | `jsonrpc` | ids, cursors, and the frames the broker writes |
//! | `server` | one server process and the offline `tools/list` client |

mod admission;
mod discovery;
mod exchange;
mod jsonrpc;
mod server;

pub(crate) use admission::admit_server;
#[cfg(test)]
pub(crate) use discovery::CompletionOutcome;
pub(crate) use discovery::{DiscoveryRegistry, DiscoveryRegistryHost, DiscoveryReleaseGuard};
pub(crate) use exchange::McpProgram;
pub(crate) use server::{RunningMcpServer, list_tools};
