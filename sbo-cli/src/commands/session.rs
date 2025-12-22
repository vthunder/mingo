//! Session storage for SBO authentication
//!
//! Stores ephemeral keys and session bindings locally at ~/.sbo/sessions/{email}.json
//! Sessions are valid until their expiry time or until manually cleared.

use anyhow::{Context, Result};
use sbo_core::crypto::SigningKey;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A stored session for an email identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// The session binding JWT (from domain)
    pub session_binding_jwt: String,
    /// Ephemeral private key (hex-encoded)
    pub ephemeral_private_key: String,
    /// When this session expires (Unix timestamp)
    pub expires_at: u64,
}

/// Get the sessions directory path
fn sessions_dir() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".sbo").join("sessions")
}

/// Get the session file path for an email
fn session_path(email: &str) -> PathBuf {
    // Sanitize email for filename (replace @ and . with _)
    let filename = email.replace('@', "_at_").replace('.', "_");
    sessions_dir().join(format!("{}.json", filename))
}

/// Get a stored session for an email
///
/// Returns None if no session exists or if it has expired.
pub fn get_session(email: &str) -> Option<Session> {
    let path = session_path(email);

    if !path.exists() {
        return None;
    }

    let contents = std::fs::read_to_string(&path).ok()?;
    let session: Session = serde_json::from_str(&contents).ok()?;

    // Check if expired
    if !is_session_valid(&session) {
        // Clean up expired session
        let _ = std::fs::remove_file(&path);
        return None;
    }

    Some(session)
}

/// Save a session for an email
pub fn save_session(
    email: &str,
    session_binding_jwt: &str,
    ephemeral_private_key: &[u8],
    expires_at: u64,
) -> Result<()> {
    let path = session_path(email);

    // Ensure directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .context("Failed to create sessions directory")?;
    }

    let session = Session {
        session_binding_jwt: session_binding_jwt.to_string(),
        ephemeral_private_key: hex::encode(ephemeral_private_key),
        expires_at,
    };

    let contents = serde_json::to_string_pretty(&session)
        .context("Failed to serialize session")?;

    std::fs::write(&path, contents)
        .context("Failed to write session file")?;

    Ok(())
}

/// Check if a session is valid (not expired)
pub fn is_session_valid(session: &Session) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    session.expires_at > now
}

/// Delete a stored session
pub fn delete_session(email: &str) -> Result<()> {
    let path = session_path(email);

    if path.exists() {
        std::fs::remove_file(&path)
            .context("Failed to delete session file")?;
    }

    Ok(())
}

/// List all stored sessions
pub fn list_sessions() -> Result<Vec<(String, Session)>> {
    let dir = sessions_dir();

    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut sessions = Vec::new();

    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().map(|e| e == "json").unwrap_or(false) {
            if let Ok(contents) = std::fs::read_to_string(&path) {
                if let Ok(session) = serde_json::from_str::<Session>(&contents) {
                    // Extract email from filename
                    let filename = path.file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("");
                    let email = filename
                        .replace("_at_", "@")
                        .replace('_', ".");

                    sessions.push((email, session));
                }
            }
        }
    }

    Ok(sessions)
}

/// Generate a new ephemeral keypair
///
/// Returns (public_key_str, secret_key_bytes)
/// public_key_str is in "ed25519:<hex>" format
pub fn generate_ephemeral_keypair() -> (String, Vec<u8>) {
    let signing_key = SigningKey::generate();
    let public_key = signing_key.public_key();

    let public_key_str = public_key.to_string();
    let secret_key_bytes = signing_key.to_bytes().to_vec();

    (public_key_str, secret_key_bytes)
}

/// Get a signing key from stored ephemeral key bytes
pub fn get_ephemeral_signing_key(session: &Session) -> Result<SigningKey> {
    let key_bytes = hex::decode(&session.ephemeral_private_key)
        .context("Invalid ephemeral key hex")?;

    if key_bytes.len() != 32 {
        anyhow::bail!("Invalid ephemeral key length");
    }

    let mut secret_key = [0u8; 32];
    secret_key.copy_from_slice(&key_bytes);

    Ok(SigningKey::from_bytes(&secret_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ephemeral_keypair() {
        let (public_key, secret_key) = generate_ephemeral_keypair();

        assert!(public_key.starts_with("ed25519:"));
        assert_eq!(secret_key.len(), 32);
    }

    #[test]
    fn test_session_validity() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let valid_session = Session {
            session_binding_jwt: "test".to_string(),
            ephemeral_private_key: "aa".repeat(32),
            expires_at: now + 3600, // 1 hour from now
        };

        let expired_session = Session {
            session_binding_jwt: "test".to_string(),
            ephemeral_private_key: "aa".repeat(32),
            expires_at: now - 3600, // 1 hour ago
        };

        assert!(is_session_valid(&valid_session));
        assert!(!is_session_valid(&expired_session));
    }
}
