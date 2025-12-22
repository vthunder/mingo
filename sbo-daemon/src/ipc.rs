//! IPC Server
//!
//! Unix socket server for CLI communication.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

/// Result of a sign request poll - returned to app
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequestResult {
    /// Status: "pending", "approved", "rejected", "expired"
    pub status: String,
    /// Auth assertion JWT (present if approved) - signed by ephemeral key
    pub assertion_jwt: Option<String>,
    /// Session binding JWT (present if approved) - signed by domain, wraps user delegation
    pub session_binding_jwt: Option<String>,
    /// Rejection reason (present if rejected)
    pub rejection_reason: Option<String>,
}

/// Response from RequestSessionBinding - returns verification URI for device flow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionBindingResponse {
    /// Request ID for polling
    pub request_id: String,
    /// URI to direct user to for verification
    pub verification_uri: String,
    /// Seconds until request expires
    pub expires_in: u64,
}

/// Response from PollSessionBinding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollSessionBindingResponse {
    /// Status: "pending", "complete", "expired"
    pub status: String,
    /// Session binding JWT (present when complete)
    pub session_binding: Option<String>,
}

/// Response from RequestIdentityProvisioning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProvisioningResponse {
    /// Status: "pending" (needs auth) or "complete" (already authenticated)
    pub status: String,
    /// Request ID for polling (present if pending)
    pub request_id: Option<String>,
    /// URI to direct user to for verification (present if pending)
    pub verification_uri: Option<String>,
    /// Seconds until request expires (present if pending)
    pub expires_in: Option<u64>,
    /// Identity JWT (present if complete)
    pub identity_jwt: Option<String>,
}

/// Response from PollIdentityProvisioning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollIdentityProvisioningResponse {
    /// Status: "pending", "complete", "expired"
    pub status: String,
    /// Identity JWT (present when complete)
    pub identity_jwt: Option<String>,
}

/// Sign request status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SignRequestStatus {
    /// Waiting for user to approve/reject
    Pending,
    /// User approved, includes signed assertion
    Approved,
    /// User rejected
    Rejected,
    /// Request expired (no response within timeout)
    Expired,
}

/// A pending sign request in the daemon queue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub request_id: String,
    pub app_name: String,
    pub app_origin: Option<String>,
    pub email: Option<String>,
    pub challenge: String,
    pub purpose: Option<String>,
    pub status: SignRequestStatus,
    pub created_at: u64,
    /// Auth assertion JWT (present if status == Approved)
    pub assertion_jwt: Option<String>,
    /// Session binding JWT (present if status == Approved)
    pub session_binding_jwt: Option<String>,
    /// Rejection reason (present if status == Rejected)
    pub rejection_reason: Option<String>,
}

/// IPC request from CLI
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd")]
pub enum Request {
    /// Add a new repo (from_block can be negative for relative to chain head)
    RepoAdd {
        display_uri: String,
        resolved_uri: String,
        path: PathBuf,
        from_block: Option<i64>,
    },
    /// Remove a repo by path
    RepoRemove { path: PathBuf },
    /// Remove a repo by URI
    RepoRemoveByUri { uri: String },
    /// List all repos
    RepoList,
    /// Re-resolve DNS and update chain reference for a repo
    RepoRelink { path: PathBuf },
    /// Get daemon status
    Status,
    /// Submit data via TurboDA
    Submit { repo_path: PathBuf, sbo_path: String, id: String, data: Vec<u8> },
    /// Get an object with optional proof
    GetObject { repo_path: PathBuf, path: String, id: String, with_proof: bool },
    /// Get a merkle proof for an object (SBOQ format)
    /// Creator is auto-detected from the stored object
    ObjectProof { repo_path: PathBuf, path: String, id: String },
    /// Submit an identity to /sys/names/<name>
    SubmitIdentity {
        /// Chain URI (e.g., sbo+raw://avail:turing:506/)
        uri: String,
        /// Name to claim
        name: String,
        /// Signed wire-format message
        data: Vec<u8>,
        /// Wait for on-chain verification
        wait: bool,
    },
    /// List identities from synced repos
    ListIdentities {
        /// Optional chain URI filter
        uri: Option<String>,
    },
    /// Get a specific identity by URI
    GetIdentity {
        /// Full URI (e.g., sbo+raw://avail:turing:506/sys/names/alice) or just name
        uri: String,
    },
    /// Submit a domain to /sys/domains/<domain_name>
    SubmitDomain {
        /// Chain URI (e.g., sbo+raw://avail:turing:506/)
        uri: String,
        /// Domain name (e.g., example.com)
        domain_name: String,
        /// Signed wire-format message
        data: Vec<u8>,
    },
    /// List domains from synced repos
    ListDomains {
        /// Optional chain URI filter
        uri: Option<String>,
    },
    /// Get a specific domain
    GetDomain {
        /// Full URI (e.g., sbo+raw://avail:turing:506/sys/domains/example.com) or just domain name
        domain: String,
    },
    /// Create a new repo with genesis (sys identity + root policy)
    RepoCreate {
        /// Display URI (what user provided - could be sbo:// or sbo+raw://)
        display_uri: String,
        /// Resolved URI (always sbo+raw://)
        resolved_uri: String,
        /// Local path to sync to
        path: PathBuf,
        /// Genesis payload (sys identity + root policy, wire format)
        genesis_data: Vec<u8>,
    },
    /// Shutdown daemon
    Shutdown,

    // ========================================================================
    // Auth / Sign Request Flow
    // ========================================================================

    /// Submit a sign request (from app) - daemon queues for user approval
    SubmitSignRequest {
        /// Unique request ID (generated by app)
        request_id: String,
        /// App name/identifier for display
        app_name: String,
        /// App origin (e.g., "https://example.com")
        app_origin: Option<String>,
        /// Requested email (for directed requests) - None for undirected
        email: Option<String>,
        /// Challenge/nonce to sign
        challenge: String,
        /// What the signature will be used for (for display)
        purpose: Option<String>,
    },

    /// List pending sign requests (for CLI)
    ListSignRequests,

    /// Get a specific sign request (for CLI)
    GetSignRequest {
        request_id: String,
    },

    /// Approve a sign request (from CLI) - includes JWTs
    ApproveSignRequest {
        request_id: String,
        /// Auth assertion JWT (signed by ephemeral key)
        assertion_jwt: String,
        /// Session binding JWT (signed by domain, wraps user delegation)
        session_binding_jwt: String,
    },

    /// Reject a sign request (from CLI)
    RejectSignRequest {
        request_id: String,
        /// Optional reason for rejection
        reason: Option<String>,
    },

    /// Poll for sign request result (from app)
    GetSignRequestResult {
        request_id: String,
    },

    // ========================================================================
    // Session Binding Flow (daemon proxies to domain endpoints)
    // ========================================================================

    /// Request a session binding from a domain (CLI → daemon → domain)
    RequestSessionBinding {
        /// Email address for the session
        email: String,
        /// Ephemeral public key (ed25519:<hex>)
        ephemeral_public_key: String,
        /// User delegation JWT (optional - domain may have custodied key)
        user_delegation_jwt: Option<String>,
    },

    /// Poll for session binding result
    PollSessionBinding {
        /// Request ID from RequestSessionBinding response
        request_id: String,
    },

    /// Request identity provisioning from a domain (CLI → daemon → domain)
    RequestIdentityProvisioning {
        /// Email address for the identity
        email: String,
        /// Public key for the identity (ed25519:<hex>)
        public_key: String,
    },

    /// Poll for identity provisioning result
    PollIdentityProvisioning {
        /// Request ID from RequestIdentityProvisioning response
        request_id: String,
    },
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
