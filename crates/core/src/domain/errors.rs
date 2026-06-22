//! Strongly-typed error hierarchy for the remote-build domain.
//!
//! Every error is a `thiserror` enum whose variants wrap concrete source types. There is
//! deliberately **no** erased `anyhow`-style catch-all: each failure mode is named, so callers
//! (and the compiler) account for all of them.

use std::path::PathBuf;

/// Failure to construct a validated domain newtype from raw input.
#[derive(Debug, thiserror::Error)]
pub enum RemoteValidationError {
    #[error("{field} must not be empty")]
    Empty { field: &'static str },
    #[error("ssh port must not be zero")]
    ZeroPort,
    #[error("{field} must not contain whitespace: {value:?}")]
    Whitespace { field: &'static str, value: String },
    #[error("invalid host_key_check {value:?} (expected accept-new, strict, or accept-all)")]
    InvalidHostKeyCheck { value: String },
}

/// Everything that can go wrong while loading or resolving remote definitions from config.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config file {path}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("config value for remote {name:?} is invalid")]
    Invalid {
        name: String,
        #[source]
        source: RemoteValidationError,
    },
    #[error("no remote named {name:?} was found in the configuration")]
    NotFound { name: String },
}

/// Everything that can go wrong while inspecting the local cargo project.
#[derive(Debug, thiserror::Error)]
pub enum MetadataError {
    #[error("failed to read cargo metadata for {manifest}")]
    Cargo {
        manifest: PathBuf,
        #[source]
        source: cargo_metadata::Error,
    },
}

/// Everything that can go wrong on the pure-Rust SSH transport (connection + auth).
#[derive(Debug, thiserror::Error)]
pub enum SshError {
    #[error("failed to connect to {host}:{port}")]
    Connect {
        host: String,
        port: u16,
        #[source]
        source: russh::Error,
    },
    #[error("no ssh user for host {host:?}; specify it explicitly as user@host")]
    NoUser { host: String },
    #[error("ssh authentication failed for {user}@{host} (tried ssh-agent and ~/.ssh keys)")]
    Auth { user: String, host: String },
    /// Key auth failed but the server still offers password login — this machine just isn't
    /// enrolled yet. The CLI can offer to install the key; the MCP server points the user at
    /// `cargo rustle setup-key`.
    #[error("{user}@{host}:{port} is not enrolled for key auth (the server requires a password)")]
    NotEnrolled { user: String, host: String, port: u16 },
    /// Installing the public key on the remote failed (after a successful password login).
    #[error("could not enroll key on {host}: {reason}")]
    EnrollFailed { host: String, reason: String },
    #[error("could not load ssh key {path}")]
    Key {
        path: PathBuf,
        #[source]
        source: russh::keys::Error,
    },
    #[error("ssh protocol error")]
    Protocol(#[from] russh::Error),
}

/// Walk an error's `source` chain looking for a [`SshError::NotEnrolled`], returning its
/// `(user, host, port)`. Lets an inbound adapter detect "this host needs key enrollment" no
/// matter how deeply the failure is wrapped (e.g. `BuildError` → `TransferError` → `SshError`).
pub fn enrollment_target(err: &(dyn std::error::Error + 'static)) -> Option<(String, String, u16)> {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = current {
        if let Some(SshError::NotEnrolled { user, host, port }) = e.downcast_ref::<SshError>() {
            return Some((user.clone(), host.clone(), *port));
        }
        current = e.source();
    }
    None
}

/// Everything that can go wrong while transferring sources to / artifacts from the remote.
#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    #[error("ssh error")]
    Ssh(#[from] SshError),
    #[error("sftp error")]
    Sftp(#[source] russh_sftp::client::error::Error),
    #[error("failed to walk local source tree")]
    Walk(#[source] walkdir::Error),
    #[error("local filesystem error at {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("remote sync agent error")]
    Agent(#[from] AgentError),
}

/// Failures specific to the remote sync agent (deploy → protocol). The agent is an optimization;
/// in `auto` sync mode any of these triggers a fall back to the native SFTP path, while in
/// `agent` mode they surface verbatim.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("failed to deploy the remote agent")]
    Deploy(#[source] SshError),
    #[error("remote agent protocol version mismatch: host speaks {host}, agent speaks {agent}")]
    Version { host: u32, agent: u32 },
    #[error("malformed or truncated frame from the remote agent")]
    Malformed,
    #[error("unexpected response from the remote agent")]
    Unexpected,
    #[error("the remote agent reported: {0}")]
    Reported(String),
    #[error("i/o error on the remote agent channel")]
    Io(#[source] std::io::Error),
}

/// Everything that can go wrong while running a command on the remote host.
#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error("ssh error")]
    Ssh(#[from] SshError),
    #[error("could not determine remote exit status")]
    NoExitStatus,
}

/// The top-level domain error: everything that can go wrong during a remote build.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("configuration error")]
    Config(#[from] ConfigError),
    #[error("no usable remote build host was specified (use config or the --remote-host flag)")]
    NoRemote,
    #[error("project metadata error")]
    Metadata(#[from] MetadataError),
    #[error("source transfer error")]
    Transfer(#[from] TransferError),
    #[error("remote execution error")]
    Exec(#[from] ExecError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrollment_target_finds_not_enrolled_through_the_chain() {
        // BuildError → TransferError → SshError::NotEnrolled (how a build surfaces it).
        let err: BuildError = TransferError::from(SshError::NotEnrolled {
            user: "echo".to_string(),
            host: "172.13.1.232".to_string(),
            port: 6922,
        })
        .into();
        assert_eq!(
            enrollment_target(&err),
            Some(("echo".to_string(), "172.13.1.232".to_string(), 6922))
        );
    }

    #[test]
    fn enrollment_target_is_none_for_unrelated_errors() {
        assert!(enrollment_target(&BuildError::NoRemote).is_none());
        let other: BuildError = TransferError::from(SshError::Auth {
            user: "x".to_string(),
            host: "h".to_string(),
        })
        .into();
        assert!(enrollment_target(&other).is_none());
    }
}
