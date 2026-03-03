//! Extension helpers for proxy types.
//! 
//! This module groups add-on functionality that builds on top of the core
//! `Proxy` and `ProxyList` types without changing their primary APIs.

pub mod proxy_list_ext;
pub mod proxy_pool_ext;

pub use proxy_list_ext::ProxyListExt;
pub use proxy_pool_ext::ProxyPoolExt;