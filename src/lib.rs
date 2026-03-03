pub mod config;
pub mod errors;
pub mod protocols;
pub mod transport;
pub mod utils;
pub mod extensions;

// Re-export commonly used types for convenience
pub use transport::{Endpoint, PoolStats, Proxy, ProxyList, ProxyPool, ProxyStream};
pub use extensions::ProxyListExt;
