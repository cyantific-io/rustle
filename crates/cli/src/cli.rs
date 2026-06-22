//! CLI inbound adapter: clap argument parsing and conversion into domain models.
//!
//! Mirrors the original `cargo rustle` flags, plus `--package` and `--workspace`.
//! All validation/mapping happens in [`RustleArgs::into_domain`], keeping `main` thin.

use std::path::PathBuf;

use clap::{Args, Parser, ValueEnum};

use rustle_core::domain::{
    BuildEnv, BuildRequest, CargoCommand, CopyBack, EnvProfile, ExtraPath, Host, HostKeyCheck,
    OutputMode, Port, RemoteDir, RemoteName, RemoteOverrides, RemoteSelector, RemoteValidationError,
    TargetSelection, Toolchain,
};
use rustle_core::outbound::{SyncMode, DEFAULT_CONCURRENCY};

/// Top-level `cargo` subcommand wrapper (invoked as `cargo rustle …`).
#[derive(Parser, Debug)]
#[command(name = "cargo", bin_name = "cargo")]
pub enum Cargo {
    /// Build a Rust project on a remote host.
    Rustle(RustleArgs),
}

/// Logging verbosity, set via `--log-level` (no env vars).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default, ValueEnum)]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub fn as_filter(self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
    }
}

/// SSH host-key verification policy (CLI value-enum).
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum HostKeyCheckArg {
    AcceptNew,
    Strict,
    AcceptAll,
}

impl From<HostKeyCheckArg> for HostKeyCheck {
    fn from(value: HostKeyCheckArg) -> Self {
        match value {
            HostKeyCheckArg::AcceptNew => HostKeyCheck::AcceptNew,
            HostKeyCheckArg::Strict => HostKeyCheck::Strict,
            HostKeyCheckArg::AcceptAll => HostKeyCheck::AcceptAll,
        }
    }
}

/// How a push reconciles remote state (CLI value-enum).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default, ValueEnum)]
pub enum SyncModeArg {
    /// Native SFTP listing/diff/prune. Always works; no remote footprint.
    Sftp,
    /// Deploy & drive the remote agent (one round-trip); fail loudly if it can't.
    Agent,
    /// Prefer the agent; on any agent failure, warn and fall back to SFTP.
    #[default]
    Auto,
}

impl From<SyncModeArg> for SyncMode {
    fn from(value: SyncModeArg) -> Self {
        match value {
            SyncModeArg::Sftp => SyncMode::Sftp,
            SyncModeArg::Agent => SyncMode::Agent,
            SyncModeArg::Auto => SyncMode::Auto,
        }
    }
}

#[derive(Args, Debug)]
#[command(version, about = "Build Rust projects on remote hosts")]
pub struct RustleArgs {
    /// The name of the remote specified in the config.
    #[arg(short = 'r', long = "remote")]
    remote: Option<String>,

    /// Remote ssh build server as user@host (ssh-config aliases are not resolved).
    #[arg(short = 'H', long = "remote-host")]
    host: Option<String>,

    /// SSH username (when not embedded in the host as user@host).
    #[arg(short = 'u', long = "user")]
    user: Option<String>,

    /// SSH host-key check: accept-new (default), strict, or accept-all (insecure).
    #[arg(long = "host-key-check", value_enum)]
    host_key_check: Option<HostKeyCheckArg>,

    /// The ssh port to communicate with the build server.
    #[arg(short = 'p', long = "remote-port")]
    port: Option<u16>,

    /// The directory where cargo builds the project on the remote.
    #[arg(short = 't', long = "remote-temp-dir")]
    temp_dir: Option<String>,

    /// Environment profile to `source` on the remote before building.
    #[arg(short = 'e', long = "env")]
    env: Option<String>,

    /// Shell command to run on the remote (in the project dir) before the build.
    #[arg(long = "setup")]
    setup: Option<String>,

    /// Extra path to sync to the remote, as <local>:<remote> (repeatable).
    #[arg(long = "extra-path", value_name = "LOCAL:REMOTE")]
    extra_paths: Vec<String>,

    /// Set remote environment variables (RUST_BACKTRACE, CC, LIB, …).
    #[arg(short = 'b', long = "build-env", default_value = "RUST_BACKTRACE=1")]
    build_env: String,

    /// Rustup default toolchain (stable|beta|nightly|…).
    #[arg(short = 'd', long = "rustup-default", default_value = "stable")]
    rustup_default: String,

    /// Transfer the target folder, or a specific file within it, back to the client.
    /// Bare `-c` copies the whole target; use `--copy-back=<path>` for a specific file.
    #[arg(short = 'c', long = "copy-back", num_args = 0..=1, require_equals = true)]
    copy_back: Option<Option<String>>,

    /// Don't transfer the Cargo.lock file back to the client.
    #[arg(long = "no-copy-lock")]
    no_copy_lock: bool,

    /// Path to the manifest to execute.
    #[arg(long = "manifest-path", default_value = "Cargo.toml")]
    manifest_path: PathBuf,

    /// Transfer hidden files and directories to the build server.
    #[arg(long = "transfer-hidden")]
    transfer_hidden: bool,

    /// Build only the named package (`cargo -p <name>`).
    #[arg(long = "package")]
    package: Option<String>,

    /// Build the entire workspace (`cargo --workspace`).
    #[arg(long = "workspace")]
    workspace: bool,

    /// Max concurrent file transfers.
    #[arg(short = 'j', long = "jobs", default_value_t = DEFAULT_CONCURRENCY)]
    jobs: usize,

    /// How a push reconciles remote state: agent (deploy a remote helper, one round-trip),
    /// sftp (native listing), or auto (agent, falling back to sftp).
    #[arg(long = "sync-mode", value_enum, default_value_t = SyncModeArg::Auto)]
    sync_mode: SyncModeArg,

    /// Public key to enroll for passwordless auth (default ~/.ssh/id_ed25519.pub). A path
    /// without a `.pub` extension has `.pub` appended. Used by `setup-key` and auto-enrollment.
    #[arg(long = "identity")]
    identity: Option<PathBuf>,

    /// Log verbosity.
    #[arg(long = "log-level", value_enum, default_value_t = LogLevel::Info)]
    log_level: LogLevel,

    /// The cargo command to run remotely (build, test, check, clippy, …).
    command: String,

    /// cargo options and flags applied remotely (after `--`).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    options: Vec<String>,
}

/// Errors converting CLI arguments into domain models.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("invalid argument: {0}")]
    Invalid(#[from] RemoteValidationError),
    #[error("invalid --extra-path {0:?}; expected <local>:<remote>")]
    BadExtraPath(String),
}

/// Parse repeatable `--extra-path <local>:<remote>` values; `None` if none were given.
fn parse_extra_paths(values: Vec<String>) -> Result<Option<Vec<ExtraPath>>, CliError> {
    if values.is_empty() {
        return Ok(None);
    }
    let mut extras = Vec::with_capacity(values.len());
    for value in values {
        match value.split_once(':') {
            Some((local, remote)) if !local.is_empty() && !remote.is_empty() => extras.push(
                ExtraPath {
                    local: PathBuf::from(local),
                    remote: remote.to_string(),
                },
            ),
            _ => return Err(CliError::BadExtraPath(value)),
        }
    }
    Ok(Some(extras))
}

impl RustleArgs {
    /// Logging verbosity selected on the command line.
    pub fn log_level(&self) -> LogLevel {
        self.log_level
    }

    /// Max concurrent file transfers selected on the command line.
    pub fn jobs(&self) -> usize {
        self.jobs
    }

    /// How a push reconciles remote state.
    pub fn sync_mode(&self) -> SyncMode {
        self.sync_mode.into()
    }

    /// Whether the invocation is the one-time `cargo rustle setup-key` enrollment command rather
    /// than a build.
    pub fn is_setup_key(&self) -> bool {
        self.command == "setup-key"
    }

    /// The public-key file to enroll, resolved (default `~/.ssh/id_ed25519.pub`; a non-`.pub`
    /// path gets `.pub` appended).
    pub fn identity(&self) -> PathBuf {
        match &self.identity {
            Some(p) if p.extension().and_then(|e| e.to_str()) == Some("pub") => p.clone(),
            Some(p) => PathBuf::from(format!("{}.pub", p.display())),
            None => dirs::home_dir()
                .unwrap_or_default()
                .join(".ssh")
                .join("id_ed25519.pub"),
        }
    }

    /// Convert parsed arguments into the validated domain request + remote selector.
    pub fn into_domain(self) -> Result<(BuildRequest, RemoteSelector), CliError> {
        let selection = if self.workspace {
            TargetSelection::Workspace
        } else if let Some(package) = self.package {
            TargetSelection::Package(package)
        } else {
            TargetSelection::Default
        };

        let copy_back = match self.copy_back {
            None => CopyBack::None,
            Some(None) => CopyBack::Target,
            Some(Some(path)) if path.is_empty() => CopyBack::Target,
            Some(Some(path)) => CopyBack::Path(path),
        };

        let request = BuildRequest {
            manifest_path: self.manifest_path,
            selection,
            command: CargoCommand::new(self.command)?,
            options: self.options,
            build_env: BuildEnv::new(self.build_env),
            toolchain: Toolchain::new(self.rustup_default)?,
            copy_back,
            copy_lock: !self.no_copy_lock,
            transfer_hidden: self.transfer_hidden,
            output: OutputMode::Inherit,
        };

        let selector = RemoteSelector {
            name: self.remote.map(RemoteName::new).transpose()?,
            overrides: RemoteOverrides {
                host: self.host.map(Host::new).transpose()?,
                user: self.user,
                port: self.port.map(Port::new).transpose()?,
                temp_dir: self.temp_dir.map(RemoteDir::new).transpose()?,
                env: self.env.map(EnvProfile::new).transpose()?,
                host_key_check: self.host_key_check.map(HostKeyCheck::from),
                setup: self.setup,
                extra_paths: parse_extra_paths(self.extra_paths)?,
            },
        };

        Ok((request, selector))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustle_core::domain::{CopyBack, TargetSelection};

    fn parse(args: &[&str]) -> RustleArgs {
        match Cargo::try_parse_from(args).expect("args should parse") {
            Cargo::Rustle(args) => args,
        }
    }

    #[test]
    fn copy_back_flag_maps_to_whole_target() {
        let (req, sel) = parse(&["cargo", "rustle", "-c", "--", "build", "--release"])
            .into_domain()
            .unwrap();
        assert!(matches!(req.copy_back, CopyBack::Target));
        assert_eq!(req.command.as_str(), "build");
        assert_eq!(req.options, vec!["--release".to_string()]);
        assert!(req.copy_lock, "lock is copied back by default on the CLI");
        assert!(sel.name.is_none());
    }

    #[test]
    fn host_override_applies() {
        let (req, sel) = parse(&["cargo", "rustle", "-H", "u@h", "check"])
            .into_domain()
            .unwrap();
        assert_eq!(req.command.as_str(), "check");
        assert_eq!(sel.overrides.host.as_ref().unwrap().as_str(), "u@h");
    }

    #[test]
    fn workspace_flag_selects_workspace() {
        let (req, _) = parse(&["cargo", "rustle", "--workspace", "build"])
            .into_domain()
            .unwrap();
        assert!(matches!(req.selection, TargetSelection::Workspace));
    }

    #[test]
    fn copy_back_with_path() {
        let (req, _) = parse(&["cargo", "rustle", "--copy-back=release/mybin", "build"])
            .into_domain()
            .unwrap();
        assert!(matches!(req.copy_back, CopyBack::Path(p) if p == "release/mybin"));
    }

    #[test]
    fn user_setup_and_extra_path_overrides() {
        let (_req, sel) = parse(&[
            "cargo", "rustle", "--user", "bob", "--setup", "ldconfig", "--extra-path",
            "/opt/foo:vendor/foo", "build",
        ])
        .into_domain()
        .unwrap();
        assert_eq!(sel.overrides.user.as_deref(), Some("bob"));
        assert_eq!(sel.overrides.setup.as_deref(), Some("ldconfig"));
        let extras = sel.overrides.extra_paths.expect("extra paths present");
        assert_eq!(extras.len(), 1);
        assert_eq!(extras[0].remote, "vendor/foo");
        assert_eq!(extras[0].local, std::path::PathBuf::from("/opt/foo"));
    }

    #[test]
    fn malformed_extra_path_errors() {
        assert!(parse(&["cargo", "rustle", "--extra-path", "noseparator", "build"])
            .into_domain()
            .is_err());
    }

    #[test]
    fn bare_copy_back_does_not_swallow_command() {
        // With require_equals, `-c build` keeps `build` as the command (whole-target copy-back).
        let (req, _) = parse(&["cargo", "rustle", "-c", "build"]).into_domain().unwrap();
        assert!(matches!(req.copy_back, CopyBack::Target));
        assert_eq!(req.command.as_str(), "build");
    }
}
