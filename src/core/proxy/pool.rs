//! Connection pool manager for upstream Pingora connections.
//!
//! Manages a pool of TCP streams to increase performance
//! by reusing existing connections instead of establishing new ones.

use deadpool::managed::{Manager, RecycleError, RecycleResult};
use std::net::SocketAddr;
use tokio::net::TcpStream;

pub struct UpstreamManager {
    addr: SocketAddr,
}

impl UpstreamManager {
    #[must_use]
    pub const fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }
}

impl Manager for UpstreamManager {
    type Type = TcpStream;
    type Error = std::io::Error;

    async fn create(&self) -> Result<TcpStream, Self::Error> {
        TcpStream::connect(self.addr).await
    }

    async fn recycle(
        &self,
        conn: &mut TcpStream,
        _: &deadpool::managed::Metrics,
    ) -> RecycleResult<Self::Error> {
        let mut buf = [0u8; 1];
        match conn.try_read(&mut buf) {
            Ok(0) => Err(RecycleError::message("connection closed")),
            Ok(_) => Err(RecycleError::message("unexpected data on connection")),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(RecycleError::Backend(e)),
        }
    }
}

pub type UpstreamPool = deadpool::managed::Pool<UpstreamManager>;

/// Creates a new connection pool for upstream connections.
///
/// # Panics
///
/// Panics if the pool builder fails to create a pool (configuration error).
#[must_use]
pub fn create_pool(addr: SocketAddr, max_size: usize) -> UpstreamPool {
    let manager = UpstreamManager::new(addr);
    UpstreamPool::builder(manager)
        .max_size(max_size)
        .build()
        .expect("Failed to create upstream pool")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_upstream_manager_new() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        let manager = UpstreamManager::new(addr);
        assert_eq!(manager.addr, addr);
    }

    #[test]
    fn test_create_pool_basic() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        let pool = create_pool(addr, 10);
        assert_eq!(pool.status().max_size, 10);
        assert_eq!(pool.status().size, 0);
    }

    #[test]
    fn test_create_pool_different_sizes() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000);
        let pool1 = create_pool(addr, 5);
        let pool2 = create_pool(addr, 20);
        assert_eq!(pool1.status().max_size, 5);
        assert_eq!(pool2.status().max_size, 20);
    }

    #[tokio::test]
    async fn test_pool_get_connection_fails_no_server() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 59999);
        let pool = create_pool(addr, 1);
        let result = pool.get().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_manager_create() {
        use deadpool::managed::Manager;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let manager = UpstreamManager::new(addr);

        let accept_handle = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let result = manager.create().await;
        assert!(result.is_ok());
        accept_handle.abort();
    }

    #[tokio::test]
    async fn test_pool_status() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 59998);
        let pool = create_pool(addr, 15);
        let status = pool.status();
        assert_eq!(status.max_size, 15);
        assert_eq!(status.size, 0);
    }
}
