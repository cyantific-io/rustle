//! Shared pure-Rust SSH connection + authentication (russh), used by both the SFTP transfer
//! adapter and the remote executor. No `ssh` binary is shelled out.
//!
//! Authentication tries ssh-agent first, then unencrypted default keys in `~/.ssh`. Host keys
//! are currently accepted without `known_hosts` verification (a noted follow-up).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use russh::client::{self, AuthResult, Handle};
use russh::keys::agent::client::AgentClient;
use russh::keys::agent::AgentIdentity;
use russh::keys::known_hosts::learn_known_hosts;
use russh::keys::{check_known_hosts, load_secret_key, Algorithm, HashAlg, PrivateKeyWithHashAlg};
use russh::{ChannelMsg, MethodKind};
use tokio::sync::Mutex as AsyncMutex;

use crate::domain::errors::SshError;
use crate::domain::models::{HostKeyCheck, Remote};

const DEFAULT_KEYS: [&str; 3] = ["id_ed25519", "id_ecdsa", "id_rsa"];

/// A shared, live SSH session. The `Handle` lock is held only to open a channel; opened
/// channels then operate independently while the session stays alive via the `Arc`.
pub type SharedConnection = Arc<AsyncMutex<Handle<ClientHandler>>>;

type ConnKey = (String, Option<String>, u16);

/// Caches one SSH connection per `(host, user, port)`, so a single command's operations
/// (push → build → pull) reuse one TCP+auth handshake instead of reconnecting each time.
/// Dead connections (e.g. idle-timed-out between MCP tool calls) are transparently replaced.
#[derive(Default)]
pub struct SshPool {
    conns: Mutex<HashMap<ConnKey, SharedConnection>>,
}

impl SshPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a shared connection to `remote`, reusing a live cached one or dialing a new one.
    pub async fn connect(&self, remote: &Remote) -> Result<SharedConnection, SshError> {
        let key = (
            remote.host.as_str().to_string(),
            remote.user.clone(),
            remote.port.get(),
        );

        let cached = self.conns.lock().unwrap().get(&key).cloned();
        if let Some(conn) = cached {
            if !conn.lock().await.is_closed() {
                return Ok(conn);
            }
        }

        let conn: SharedConnection = Arc::new(AsyncMutex::new(connect_new(remote).await?));
        self.conns.lock().unwrap().insert(key, conn.clone());
        Ok(conn)
    }

    /// Verify we can authenticate to `remote` with key auth (and cache the connection). Returns
    /// [`SshError::NotEnrolled`] when the key is rejected but the server still offers a password
    /// — the signal for the CLI to offer key enrollment.
    pub async fn ensure_authenticated(&self, remote: &Remote) -> Result<(), SshError> {
        self.connect(remote).await.map(|_| ())
    }

    /// Install `public_key` into the remote's `~/.ssh/authorized_keys` after a one-time **password**
    /// login (the `ssh-copy-id` step, done in pure Rust). Idempotent and permission-correct. The
    /// password is used only for this single authentication and never stored or logged.
    pub async fn enroll_key(
        &self,
        remote: &Remote,
        password: &str,
        public_key: &str,
    ) -> Result<(), SshError> {
        let (user, host) = user_and_host(remote)?;
        let port = remote.port.get();
        let key = public_key.trim();
        // The key is single-quoted into a remote shell command; reject anything that could break
        // out of the quoting (a valid OpenSSH public key contains neither).
        if key.is_empty() || key.contains('\'') || key.contains('\n') {
            return Err(SshError::EnrollFailed {
                host: host.clone(),
                reason: "public key is empty or contains unsafe characters".to_string(),
            });
        }

        let mut handle = dial(remote, &host, port).await?;
        let result = handle
            .authenticate_password(&user, password)
            .await
            .map_err(SshError::Protocol)?;
        if !result.success() {
            return Err(SshError::Auth { user, host });
        }

        // Create ~/.ssh (700) + authorized_keys (600), then append the key only if absent.
        let command = format!(
            "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && \
             chmod 600 ~/.ssh/authorized_keys && \
             {{ grep -qxF '{key}' ~/.ssh/authorized_keys || printf '%s\\n' '{key}' >> ~/.ssh/authorized_keys; }}"
        );
        let code = run_command(&handle, &command).await?;
        if code != 0 {
            return Err(SshError::EnrollFailed {
                host,
                reason: format!("remote install command exited with status {code}"),
            });
        }
        Ok(())
    }
}

/// Run a command over an exec channel and return its exit status.
async fn run_command(handle: &Handle<ClientHandler>, command: &str) -> Result<i32, SshError> {
    let mut channel = handle.channel_open_session().await.map_err(SshError::Protocol)?;
    channel.exec(true, command.as_bytes()).await.map_err(SshError::Protocol)?;
    let mut code = None;
    while let Some(msg) = channel.wait().await {
        if let ChannelMsg::ExitStatus { exit_status } = msg {
            code = Some(exit_status as i32);
        }
    }
    Ok(code.unwrap_or(-1))
}

/// Modern OpenSSH rejects SHA-1 (`ssh-rsa`); use rsa-sha2-512 for RSA keys, default otherwise.
fn hash_alg_for(algorithm: Algorithm) -> Option<HashAlg> {
    if algorithm.is_rsa() {
        Some(HashAlg::Sha512)
    } else {
        None
    }
}

/// russh client handler that verifies the server's host key against `~/.ssh/known_hosts`
/// per the configured [`HostKeyCheck`] policy.
pub struct ClientHandler {
    host: String,
    port: u16,
    policy: HostKeyCheck,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        if self.policy == HostKeyCheck::AcceptAll {
            return Ok(true);
        }
        match check_known_hosts(&self.host, self.port, server_public_key) {
            // Recorded and matches.
            Ok(true) => Ok(true),
            // Host not in known_hosts.
            Ok(false) => {
                if self.policy == HostKeyCheck::AcceptNew {
                    match learn_known_hosts(&self.host, self.port, server_public_key) {
                        Ok(()) => tracing::info!(
                            host = %self.host,
                            "recorded new host key in ~/.ssh/known_hosts"
                        ),
                        Err(e) => tracing::warn!(
                            host = %self.host, error = %e,
                            "accepted new host key but could not record it"
                        ),
                    }
                    Ok(true)
                } else {
                    tracing::error!(
                        host = %self.host,
                        "host key is not in known_hosts (strict policy) — refusing to connect"
                    );
                    Ok(false)
                }
            }
            // Host IS known but with a different key — possible MITM. Always refuse.
            Err(e) => {
                tracing::error!(
                    host = %self.host, error = %e,
                    "host key does not match the recorded known_hosts entry — refusing to connect"
                );
                Ok(false)
            }
        }
    }
}

/// Resolve `(user, host)`, requiring an explicit user. The username is never guessed:
/// an explicit `remote.user` (the `--user` flag / `user =` config) wins, else a `user@` prefix
/// in the host; with neither, this errors.
fn user_and_host(remote: &Remote) -> Result<(String, String), SshError> {
    let raw = remote.host.as_str();
    let (embedded_user, hostname) = match raw.split_once('@') {
        Some((user, host)) => (Some(user), host),
        None => (None, raw),
    };
    let user = remote.user.as_deref().or(embedded_user);
    match (user, hostname) {
        (Some(user), host) if !user.is_empty() && !host.is_empty() => {
            Ok((user.to_string(), host.to_string()))
        }
        _ => Err(SshError::NoUser {
            host: raw.to_string(),
        }),
    }
}

/// Open a TCP session and run host-key verification (no authentication yet).
async fn dial(
    remote: &Remote,
    host: &str,
    port: u16,
) -> Result<Handle<ClientHandler>, SshError> {
    let config = Arc::new(client::Config::default());
    let handler = ClientHandler {
        host: host.to_string(),
        port,
        policy: remote.host_key_check,
    };
    client::connect(config, (host, port), handler)
        .await
        .map_err(|source| SshError::Connect {
            host: host.to_string(),
            port,
            source,
        })
}

/// Dial + authenticate a fresh session (used by the pool; callers should use [`SshPool`]).
async fn connect_new(remote: &Remote) -> Result<Handle<ClientHandler>, SshError> {
    let (user, host) = user_and_host(remote)?;
    let port = remote.port.get();
    let mut handle = dial(remote, &host, port).await?;
    authenticate(&mut handle, &user, &host, port).await?;
    Ok(handle)
}

/// Note whether a failed auth attempt left `password` among the server's still-offered methods.
fn records_password(result: &AuthResult, password_offered: &mut bool) {
    if let AuthResult::Failure { remaining_methods, .. } = result {
        if remaining_methods.contains(&MethodKind::Password) {
            *password_offered = true;
        }
    }
}

async fn authenticate(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    host: &str,
    port: u16,
) -> Result<(), SshError> {
    let mut password_offered = false;

    // 1. ssh-agent.
    if let Ok(mut agent) = AgentClient::connect_env().await {
        if let Ok(identities) = agent.request_identities().await {
            for identity in identities {
                if let AgentIdentity::PublicKey { key, .. } = identity {
                    let hash = hash_alg_for(key.algorithm());
                    if let Ok(result) = handle
                        .authenticate_publickey_with(user, key, hash, &mut agent)
                        .await
                    {
                        if result.success() {
                            return Ok(());
                        }
                        records_password(&result, &mut password_offered);
                    }
                }
            }
        }
    }

    // 2. Default unencrypted key files in ~/.ssh.
    if let Some(home) = dirs::home_dir() {
        for name in DEFAULT_KEYS {
            let path = home.join(".ssh").join(name);
            if !path.is_file() {
                continue;
            }
            let Ok(key) = load_secret_key(&path, None) else {
                continue; // encrypted / unreadable — skip
            };
            let hash = hash_alg_for(key.algorithm());
            let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash);
            if let Ok(result) = handle.authenticate_publickey(user, key).await {
                if result.success() {
                    return Ok(());
                }
                records_password(&result, &mut password_offered);
            }
        }
    }

    // Key auth failed. If the server still offers a password, we're simply not enrolled yet —
    // surface that distinctly so the CLI can offer to install the key.
    if password_offered {
        Err(SshError::NotEnrolled {
            user: user.to_string(),
            host: host.to_string(),
            port,
        })
    } else {
        Err(SshError::Auth {
            user: user.to_string(),
            host: host.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::{EnvProfile, Host, Port, RemoteDir};

    fn remote(host: &str, user: Option<&str>) -> Remote {
        Remote {
            name: None,
            host: Host::new(host).unwrap(),
            user: user.map(str::to_string),
            port: Port::default(),
            temp_dir: RemoteDir::new("~/x").unwrap(),
            env: EnvProfile::new("/etc/profile").unwrap(),
            host_key_check: HostKeyCheck::AcceptAll,
            setup: None,
            extra_paths: Vec::new(),
        }
    }

    #[test]
    fn user_embedded_in_host() {
        assert_eq!(
            user_and_host(&remote("bob@srv", None)).unwrap(),
            ("bob".to_string(), "srv".to_string())
        );
    }

    #[test]
    fn explicit_user_field_wins_over_embedded() {
        assert_eq!(
            user_and_host(&remote("bob@srv", Some("alice"))).unwrap(),
            ("alice".to_string(), "srv".to_string())
        );
    }

    #[test]
    fn separate_user_for_bare_host() {
        assert_eq!(
            user_and_host(&remote("srv", Some("alice"))).unwrap(),
            ("alice".to_string(), "srv".to_string())
        );
    }

    #[test]
    fn missing_user_is_an_error_not_a_guess() {
        assert!(matches!(
            user_and_host(&remote("srv", None)),
            Err(SshError::NoUser { .. })
        ));
    }
}
