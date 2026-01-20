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

    async fn get_info_config_text(&self) -> Result<Vec<String>, String> {
        let mut stream = TcpStream::connect(self.addr)
            .await
            .map_err(|e| e.to_string())?;
        self.authenticate(&mut stream).await?;

        let cmd = "GETINFO config-text\r\n";
        stream
            .write_all(cmd.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;

        let mut reader = BufReader::new(stream);
        let mut lines = Vec::new();
        let mut in_config = false;

        loop {
            let mut line = String::new();
            let bytes = reader
                .read_line(&mut line)
                .await
                .map_err(|e| e.to_string())?;
            if bytes == 0 {
                break;
            }

            if line.starts_with("250+config-text=") {
                in_config = true;
                continue;
            } else if line.trim() == "." || (line.starts_with("250 OK") && !in_config) {
                break;
            }

            if in_config {
                let trimmed = line.trim().to_string();
                if !trimmed.is_empty() {
                    lines.push(trimmed);
                }
            }
        }
        Ok(lines)
    }

    /// Enables Proof-of-Work defense on ALL configured hidden services.
    ///
    /// # Errors
    ///
    /// Returns an error if Tor control connection or authentication fails.
    pub async fn enable_pow(&self, _onion_addr: &str, effort: u32) -> Result<(), String> {
        use std::fmt::Write;
        let current_conf = self.get_info_config_text().await?;
        let mut new_conf = String::from("+LOADCONF\r\n");
        let mut current_block = String::new();
        let mut is_hs_block = false;
        let mut found_any_hs = false;

        for line in current_conf {
            if line.starts_with("HiddenServiceDir") {
                if !current_block.is_empty() {
                    new_conf.push_str(&current_block);
                }

                current_block.clear();
                current_block.push_str(&line);
                current_block.push_str("\r\n");
                is_hs_block = true;
                found_any_hs = true;

                let _ = write!(
                    current_block,
                    "HiddenServiceEnableIntroDoSDefense 1\r\nHiddenServicePoWDefensesEnabled 1\r\nHiddenServicePoWQueueRate {}\r\nHiddenServicePoWQueueBurst {}\r\n",
                    effort,
                    effort * 2
                );
            } else {
                if is_hs_block
                    && (line.starts_with("HiddenServicePoW")
                        || line.starts_with("HiddenServiceEnableIntroDoS"))
                {
                    continue;
                }
                current_block.push_str(&line);
                current_block.push_str("\r\n");
            }
        }

        if !current_block.is_empty() {
            new_conf.push_str(&current_block);
        }

        if !found_any_hs {
            return Err("No HiddenServiceDir found in config".to_string());
        }

        new_conf.push_str(".\r\n");

        let mut stream = TcpStream::connect(self.addr)
            .await
            .map_err(|e| e.to_string())?;
        self.authenticate(&mut stream).await?;

        stream
            .write_all(new_conf.as_bytes())
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
            info!(
                effort = effort,
                "Tor PoW enabled for all services (LOADCONF)"
            );
            Ok(())
        } else {
            Err(format!("PoW config failed: {response}"))
        }
    }

    /// Disables Proof-of-Work defense on ALL configured hidden services.
    ///
    /// # Errors
    ///
    /// Returns an error if Tor control command fails.
    pub async fn disable_pow(&self) -> Result<(), String> {
        let current_conf = self.get_info_config_text().await?;
        let mut new_conf = String::from("+LOADCONF\r\n");
        let mut current_block = String::new();
        let mut is_hs_block = false;
        let mut found_any_hs = false;

        for line in current_conf {
            if line.starts_with("HiddenServiceDir") {
                if !current_block.is_empty() {
                    new_conf.push_str(&current_block);
                }

                current_block.clear();
                current_block.push_str(&line);
                current_block.push_str("\r\n");
                is_hs_block = true;
                found_any_hs = true;
            } else {
                if is_hs_block
                    && (line.starts_with("HiddenServicePoW")
                        || line.starts_with("HiddenServiceEnableIntroDoS"))
                {
                    continue;
                }
                current_block.push_str(&line);
                current_block.push_str("\r\n");
            }
        }

        if !current_block.is_empty() {
            new_conf.push_str(&current_block);
        }

        if !found_any_hs {
            return Err("No HiddenServiceDir found in config".to_string());
        }

        new_conf.push_str(".\r\n");

        let mut stream = TcpStream::connect(self.addr)
            .await
            .map_err(|e| e.to_string())?;
        self.authenticate(&mut stream).await?;

        stream
            .write_all(new_conf.as_bytes())
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
            info!("Tor PoW disabled for all services (LOADCONF)");
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
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    #[test]
    fn test_tor_control_new() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9051);
        let control = TorControl::new(addr, Some("secret".to_string()));
        assert!(control.password.is_some());
    }

    async fn spawn_mock_tor(responses: Vec<String>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let responses = Arc::new(Mutex::new(responses.into_iter()));

        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let responses_clone = responses.clone();

                tokio::spawn(async move {
                    let mut reader = BufReader::new(&mut socket);
                    let mut line = String::new();

                    if reader.read_line(&mut line).await.is_ok() {
                        let _ = reader.get_mut().write_all(b"250 OK\r\n").await;
                    }

                    loop {
                        line.clear();
                        if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                            break;
                        }

                        let mut resp_guard = responses_clone.lock().await;

                        if line.starts_with("GETINFO config-text") {
                            if let Some(resp) = resp_guard.next() {
                                let _ = reader.get_mut().write_all(resp.as_bytes()).await;
                            } else {
                                let _ = reader.get_mut().write_all(b"250+config-text=\r\nHiddenServiceDir /tmp/hs\r\nHiddenServicePort 80\r\n.\r\n250 OK\r\n").await;
                            }
                        } else if line.starts_with("+LOADCONF") || line.starts_with("CLOSECIRCUIT")
                        {
                            if let Some(resp) = resp_guard.next() {
                                let _ = reader.get_mut().write_all(resp.as_bytes()).await;
                            } else {
                                let _ = reader.get_mut().write_all(b"250 OK\r\n").await;
                            }
                        }
                    }
                });
            }
        });

        addr
    }

    #[tokio::test]
    async fn test_enable_pow() {
        let responses = vec![
            "250+config-text=\r\nSocksPort 9050\r\nHiddenServiceDir /var/lib/tor/other_service/\r\nHiddenServicePort 80 127.0.0.1:8081\r\nHiddenServiceDir /var/lib/tor/hidden_service/test_service/\r\nHiddenServicePort 80 127.0.0.1:8080\r\n.\r\n250 OK\r\n".to_string(),
            "250 OK\r\n".to_string(),
        ];
        let addr = spawn_mock_tor(responses).await;
        let control = TorControl::new(addr, Some("pass".into()));

        let res = control.enable_pow("onion.onion", 10).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_disable_pow() {
        let responses = vec![
            "250+config-text=\r\nSocksPort 9050\r\nHiddenServiceDir /var/lib/tor/other_service/\r\nHiddenServicePort 80 127.0.0.1:8081\r\nHiddenServiceDir /var/lib/tor/hidden_service/test_service/\r\nHiddenServicePort 80 127.0.0.1:8080\r\nHiddenServicePoWDefensesEnabled 1\r\n.\r\n250 OK\r\n".to_string(),
            "250 OK\r\n".to_string(),
        ];
        let addr = spawn_mock_tor(responses).await;
        let control = TorControl::new(addr, Some("pass".into()));

        let res = control.disable_pow().await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_kill_circuit() {
        let responses = vec!["250 OK\r\n".to_string()];
        let addr = spawn_mock_tor(responses).await;
        let control = TorControl::new(addr, Some("pass".into()));

        let res = control.kill_circuit("123").await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_kill_circuit_failure() {
        let responses = vec!["551 Unknown circuit\r\n".to_string()];
        let addr = spawn_mock_tor(responses).await;
        let control = TorControl::new(addr, Some("pass".into()));

        let res = control.kill_circuit("123").await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_enable_pow_no_hs() {
        let responses = vec!["250+config-text=\r\nControlPort 9051\r\n.\r\n250 OK\r\n".to_string()];
        let addr = spawn_mock_tor(responses).await;
        let control = TorControl::new(addr, Some("pass".into()));

        let res = control.enable_pow("onion", 10).await;
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
        let responses = vec![
            "250+config-text=\r\nHiddenServiceDir /var/lib/tor/hidden_service/test_service/\r\nHiddenServicePort 80 127.0.0.1:8080\r\n.\r\n250 OK\r\n".to_string(),
            "500 Internal Error\r\n".to_string(),
        ];
        let addr = spawn_mock_tor(responses).await;
        let control = TorControl::new(addr, Some("pass".into()));

        let res = control.enable_pow("onion", 10).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_disable_pow_failure() {
        let responses = vec![
            "250+config-text=\r\nHiddenServiceDir /var/lib/tor/hidden_service/test_service/\r\nHiddenServicePort 80 127.0.0.1:8080\r\n.\r\n250 OK\r\n".to_string(),
            "500 Internal Error\r\n".to_string(),
        ];
        let addr = spawn_mock_tor(responses).await;
        let control = TorControl::new(addr, Some("pass".into()));

        let res = control.disable_pow().await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_kill_circuit_already_closed() {
        let responses = vec!["552 Unknown circuit\r\n".to_string()];
        let addr = spawn_mock_tor(responses).await;
        let control = TorControl::new(addr, Some("pass".into()));

        let res = control.kill_circuit("123").await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_enable_pow_state_leak() {
        let responses = vec![
            "250+config-text=\r\nHiddenServiceDir /var/lib/tor/hidden_service/test_service/\r\nHiddenServicePort 80 127.0.0.1:8080\r\nHiddenServiceDir\r\n# Malformed line above treated as new block start\r\nHiddenServicePort 80 127.0.0.1:9090\r\n.\r\n250 OK\r\n".to_string(),
            "250 OK\r\n".to_string(),
        ];
        let addr = spawn_mock_tor(responses).await;
        let control = TorControl::new(addr, Some("pass".into()));

        let res = control.enable_pow("onion.onion", 10).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_enable_pow_dynamic_target() {
        let responses = vec![
            "250+config-text=\r\nHiddenServiceDir /var/lib/tor/hidden_service/default/\r\nHiddenServicePort 80 127.0.0.1:9090\r\nHiddenServiceDir /var/lib/tor/custom_service/\r\nHiddenServicePort 80 127.0.0.1:8080\r\n.\r\n250 OK\r\n".to_string(),
            "250 OK\r\n".to_string(),
        ];

        let addr = spawn_mock_tor(responses).await;
        let control = TorControl::new(addr, Some("pass".into()));

        let res = control.enable_pow("onion.onion", 10).await;

        assert!(res.is_ok());
    }
}
