//! Proxy connection from node to VLS.
//! In particular, a replacement for CLN's hsmd binary.

pub mod client;
pub mod connection;
pub mod grpc;
pub mod nodefront;
pub mod portfront;
#[cfg(feature = "splice_trace")]
pub mod trace_tap;

#[macro_use]
#[allow(unused_macros)]
pub mod util;

pub use lightning_signer;
pub use vls_frontend;
pub use vls_protocol_client;
pub use vls_protocol_signer;
