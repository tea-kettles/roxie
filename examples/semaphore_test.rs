//! Minimal example of dialing a target through proxies with a bounded semaphore.
//!
//! Reads proxies from `tests/proxies.json`, limits concurrent connections, and
//! attempts to connect each task to `https://example.com/` using
//! `ProxyListExt::connect_with_semaphore`.
//!
//! Run with:
//! ```bash
//! cargo run --example semaphore_test
//! ```

use std::error::Error;
use std::sync::Arc;

use roxie::extensions::ProxyListExt;
use roxie::transport::ProxyList;
use tokio::sync::Semaphore;
use tracing::{debug, warn};
use tracing_subscriber;
use url::Url;

const PROXY_FILE: &str = "./tests/proxies.json";
const TARGET_URL: &str = "https://example.com/";
const MAX_CONCURRENCY: usize = 100;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_test_writer()
        .init();

    let proxies_json = std::fs::read_to_string(PROXY_FILE)?;
    let list = ProxyList::from_array(&proxies_json)?;

    let target = Url::parse(TARGET_URL)?;
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENCY));

    let mut attempt: usize = 0;
    loop {
        debug!(attempt, %target, "dial start");
        match list.connect_with_semaphore(&target, &semaphore).await {
            Ok(Some(_stream)) => {
                debug!(attempt, %target, "connected");
                return Ok(());
            }
            Ok(None) => {
                debug!(attempt, %target, "proxy list empty");
                return Ok(());
            }
            Err(err) => {
                warn!(attempt, %target, error = %err, "connect failed");
                attempt = attempt.wrapping_add(1);
            }
        }
    }
}
