//! IPC Server
//!
//! Unix socket server for CLI communication.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

/// IPC request from CLI
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd")]
pub enum Request {
    /// Add a new repo (from_block can be negative for relative to chain head)
    RepoAdd { uri: String, path: PathBuf, from_block: Option<i64> },
    /// Remove a repo by path
    RepoRemove { path: PathBuf },
    /// Remove a repo by URI
    RepoRemoveByUri { uri: String },
    /// List all repos
    RepoList,
    /// Get daemon status
    Status,
    /// Submit data via TurboDA
    Submit { repo_path: PathBuf, sbo_path: String, id: String, data: Vec<u8> },
    /// Get an object with optional proof
    GetObject { repo_path: PathBuf, path: String, id: String, with_proof: bool },
    /// Get a merkle proof for an object (SBOQ format)
    /// Creator is auto-detected from the stored object
    ObjectProof { repo_path: PathBuf, path: String, id: String },
    /// Shutdown daemon
    Shutdown,
}

/// IPC response to CLI
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum Response {
    Ok { data: serde_json::Value },
    Error { message: String },
}

impl Response {
    pub fn ok<T: Serialize>(data: T) -> Self {
        Self::Ok {
            data: serde_json::to_value(data).unwrap_or(serde_json::Value::Null),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self::Error {
            message: message.into(),
        }
    }
}

/// IPC server
pub struct IpcServer {
    socket_path: PathBuf,
}

impl IpcServer {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    /// Start the IPC server
    pub async fn run<F, Fut>(&self, handler: F) -> crate::Result<()>
    where
        F: Fn(Request) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = Response> + Send,
    {
        // Remove existing socket
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }

        // Create parent directory
        if let Some(parent) = self.socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(&self.socket_path)
            .map_err(|e| crate::DaemonError::Ipc(format!("Failed to bind socket: {}", e)))?;

        tracing::info!("IPC server listening on {}", self.socket_path.display());

        loop {
            let (stream, _) = listener.accept().await?;
            let handler = handler.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(stream, handler).await {
                    tracing::error!("IPC connection error: {}", e);
                }
            });
        }
    }

    async fn handle_connection<F, Fut>(stream: UnixStream, handler: F) -> crate::Result<()>
    where
        F: Fn(Request) -> Fut,
        Fut: std::future::Future<Output = Response>,
    {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        while reader.read_line(&mut line).await? > 0 {
            let request: Request = match serde_json::from_str(&line) {
                Ok(req) => req,
                Err(e) => {
                    let resp = Response::error(format!("Invalid request: {}", e));
                    let resp_json = serde_json::to_string(&resp).unwrap();
                    writer.write_all(resp_json.as_bytes()).await?;
                    writer.write_all(b"\n").await?;
                    line.clear();
                    continue;
                }
            };

            let response = handler(request).await;
            let resp_json = serde_json::to_string(&response).unwrap();
            writer.write_all(resp_json.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;

            line.clear();
        }

        Ok(())
    }
}

/// IPC client for CLI
pub struct IpcClient {
    socket_path: PathBuf,
}

impl IpcClient {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    /// Send a request and receive response
    pub async fn request(&self, req: Request) -> crate::Result<Response> {
        let stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| crate::DaemonError::Ipc(format!(
                "Failed to connect to daemon (is it running?): {}", e
            )))?;

        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        // Send request
        let req_json = serde_json::to_string(&req)
            .map_err(|e| crate::DaemonError::Ipc(format!("Failed to serialize request: {}", e)))?;
        writer.write_all(req_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;

        // Read response
        let mut line = String::new();
        reader.read_line(&mut line).await?;

        serde_json::from_str(&line)
            .map_err(|e| crate::DaemonError::Ipc(format!("Failed to parse response: {}", e)))
    }
}
