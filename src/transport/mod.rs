pub mod endpoint;
pub mod proxy;
pub mod proxy_list;
pub mod proxy_pool;
pub mod streams;
#[cfg(feature = "tls")]
pub mod tls;

// Re-export commonly used types
pub use endpoint::{Endpoint, idna_encode, parse_ip, resolve_host};
pub use proxy::Proxy;
pub use proxy_list::ProxyList;
pub use proxy_pool::{PoolStats, ProxyPool};
pub use streams::ProxyStream;
#[cfg(feature = "tls")]
pub use tls::establish_tls;
