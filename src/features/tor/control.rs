//! Tor control protocol integration.
//!
//! Provides interface to Tor control port for `PoW` configuration.

use std::net::SocketAddr;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, error, info};

#[derive(Clone)]
pub struct TorControl {
    addr: SocketAddr,
    password: Option<String>,
}

impl TorControl {
    /// Creates a new `TorControl` instance.
    #[must_use]
    pub const fn new(addr: SocketAddr, password: Option<String>) -> Self {
        Self { addr, password }
    }

    async fn authenticate(&self, stream: &mut TcpStream) -> Result<(), String> {
        let auth_cmd = self.password.as_ref().map_or_else(
            || "AUTHENTICATE\r\n".to_string(),
            |pw| format!("AUTHENTICATE \"{pw}\"\r\n"),
        );

        stream
            .write_all(auth_cmd.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;

        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader
            .read_line(&mut response)
            .await
            .map_err(|e| e.to_string())?;

        if response.starts_with("250") {
            debug!("Tor control: authenticated");
            Ok(())
        } else {
            error!(response = %response.trim(), "Tor control: authentication failed");
            Err(format!("Auth failed: {response}"))
        }
    }

    /// Enables Proof-of-Work defense on the hidden service.
    ///
    /// # Errors
    ///
    /// Returns an error if Tor control connection or authentication fails.
    pub async fn enable_pow(&self, onion_addr: &str, effort: u32) -> Result<(), String> {
        let mut stream = TcpStream::connect(self.addr)
            .await
            .map_err(|e| e.to_string())?;
        self.authenticate(&mut stream).await?;

        let cmd = format!(
            "SETCONF HiddenServiceEnableIntroDoSDefense=1 HiddenServicePoWDefensesEnabled=1 HiddenServicePoWQueueRate={} HiddenServicePoWQueueBurst={}\r\n",
            effort,
            effort * 2
        );

        stream
            .write_all(cmd.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;

        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader
            .read_line(&mut response)
            .await
            .map_err(|e| e.to_string())?;

        if response.starts_with("250") {
            info!(onion = %onion_addr, effort = effort, "Tor PoW enabled");
            Ok(())
        } else {
            Err(format!("PoW config failed: {response}"))
        }
    }

    /// Disables Proof-of-Work defense.
    ///
    /// # Errors
    ///
    /// Returns an error if Tor control command fails.
    pub async fn disable_pow(&self) -> Result<(), String> {
        let mut stream = TcpStream::connect(self.addr)
            .await
            .map_err(|e| e.to_string())?;
        self.authenticate(&mut stream).await?;

        let cmd = "SETCONF HiddenServicePoWDefensesEnabled=0\r\n";
        stream
            .write_all(cmd.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;

        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader
            .read_line(&mut response)
            .await
            .map_err(|e| e.to_string())?;

        if response.starts_with("250") {
            info!("Tor PoW disabled");
            Ok(())
        } else {
            Err(format!("PoW disable failed: {response}"))
        }
    }

    /// Kills a specific Tor circuit.
    ///
    /// # Errors
    ///
    /// Returns an error if the circuit cannot be found or killed.
    pub async fn kill_circuit(&self, circuit_id: &str) -> Result<(), String> {
        use crate::features::tor::circuit::decode_circuit_id;
        let numeric_id = decode_circuit_id(circuit_id).unwrap_or_else(|| circuit_id.to_string());

        debug!(circuit_id = %circuit_id, numeric_id = %numeric_id, "Killing circuit");
        let mut stream = TcpStream::connect(self.addr)
            .await
            .map_err(|e| e.to_string())?;
        self.authenticate(&mut stream).await?;

        let cmd = format!("CLOSECIRCUIT {numeric_id}\r\n");

        stream
            .write_all(cmd.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;

        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader
            .read_line(&mut response)
            .await
            .map_err(|e| e.to_string())?;

        if response.starts_with("250") {
            info!(circuit_id = %circuit_id, "Circuit killed");
            Ok(())
        } else if response.contains("552") {
            debug!(circuit_id = %circuit_id, "Circuit already closed");
            Ok(())
        } else {
            error!(circuit_id = %circuit_id, response = %response.trim(), "Failed to kill circuit");
            Err(format!("Kill failed: {response}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[test]
    fn test_tor_control_new() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9051);
        let control = TorControl::new(addr, Some("secret".to_string()));
        assert!(control.password.is_some());
    }

    async fn spawn_mock_tor(responses: Vec<&'static str>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];

            let _ = socket.read(&mut buf).await.unwrap();
            socket.write_all(b"250 OK\r\n").await.unwrap();

            for resp in responses {
                let _ = socket.read(&mut buf).await.unwrap();
                socket.write_all(resp.as_bytes()).await.unwrap();
            }
        });

        addr
    }

    #[tokio::test]
    async fn test_enable_pow() {
        let addr = spawn_mock_tor(vec!["250 OK\r\n"]).await;
        let control = TorControl::new(addr, Some("pass".into()));

        let res = control.enable_pow("onion.onion", 10).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_disable_pow() {
        let addr = spawn_mock_tor(vec!["250 OK\r\n"]).await;
        let control = TorControl::new(addr, Some("pass".into()));

        let res = control.disable_pow().await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_kill_circuit() {
        let addr = spawn_mock_tor(vec!["250 OK\r\n"]).await;
        let control = TorControl::new(addr, Some("pass".into()));

        let res = control.kill_circuit("123").await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_kill_circuit_failure() {
        let addr = spawn_mock_tor(vec!["551 Unknown circuit\r\n"]).await;
        let control = TorControl::new(addr, Some("pass".into()));

        let res = control.kill_circuit("123").await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_authenticate_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await.unwrap();
            socket
                .write_all(b"515 Authentication failed\r\n")
                .await
                .unwrap();
        });

        let control = TorControl::new(addr, Some("pass".into()));
        let res = control.enable_pow("onion", 10).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Auth failed"));
    }

    #[tokio::test]
    async fn test_enable_pow_failure() {
        let addr = spawn_mock_tor(vec!["500 Internal Error\r\n"]).await;
        let control = TorControl::new(addr, Some("pass".into()));

        let res = control.enable_pow("onion", 10).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_disable_pow_failure() {
        let addr = spawn_mock_tor(vec!["500 Internal Error\r\n"]).await;
        let control = TorControl::new(addr, Some("pass".into()));

        let res = control.disable_pow().await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_kill_circuit_already_closed() {
        let addr = spawn_mock_tor(vec!["552 Unknown circuit\r\n"]).await;
        let control = TorControl::new(addr, Some("pass".into()));

        let res = control.kill_circuit("123").await;
        assert!(res.is_ok());
    }
}
