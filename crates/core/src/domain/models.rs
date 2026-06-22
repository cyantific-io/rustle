//! Validated domain models for the remote-build domain.
//!
//! These types are the canonical, always-valid representation of build inputs. Adapters
//! (CLI, MCP, config files) convert their own transport DTOs into these models via the
//! constructors here; invalid input is rejected at the boundary. Note the deliberate absence
//! of `serde` derives — these types validate, so we never let an adapter bypass their
//! constructors by deserializing straight into them.

use std::path::PathBuf;

use super::errors::RemoteValidationError;

/// A non-empty, whitespace-free SSH host as `user@host` (ssh-config aliases are not resolved).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Host(String);

impl Host {
    pub fn new(value: impl Into<String>) -> Result<Self, RemoteValidationError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(RemoteValidationError::Empty { field: "host" });
        }
        if value.split_whitespace().count() != 1 {
            return Err(RemoteValidationError::Whitespace { field: "host", value });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A TCP port for SSH (non-zero).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Port(u16);

impl Port {
    pub fn new(port: u16) -> Result<Self, RemoteValidationError> {
        if port == 0 {
            return Err(RemoteValidationError::ZeroPort);
        }
        Ok(Self(port))
    }

    pub fn get(self) -> u16 {
        self.0
    }
}

impl Default for Port {
    fn default() -> Self {
        Self(22)
    }
}

impl std::fmt::Display for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The name a remote is referred to by in the config.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RemoteName(String);

impl RemoteName {
    pub fn new(value: impl Into<String>) -> Result<Self, RemoteValidationError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(RemoteValidationError::Empty { field: "remote name" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RemoteName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The base directory on the remote under which per-project build dirs are created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteDir(String);

impl RemoteDir {
    pub fn new(value: impl Into<String>) -> Result<Self, RemoteValidationError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(RemoteValidationError::Empty { field: "temp dir" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A shell profile to `source` before building (e.g. `/etc/profile`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvProfile(String);

impl EnvProfile {
    pub fn new(value: impl Into<String>) -> Result<Self, RemoteValidationError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(RemoteValidationError::Empty { field: "env profile" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A rustup toolchain name (`stable`, `beta`, `nightly`, or a custom channel).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toolchain(String);

impl Toolchain {
    pub fn new(value: impl Into<String>) -> Result<Self, RemoteValidationError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(RemoteValidationError::Empty { field: "toolchain" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for Toolchain {
    fn default() -> Self {
        Self("stable".to_string())
    }
}

/// A cargo subcommand to run remotely (`build`, `test`, `check`, `clippy`, …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoCommand(String);

impl CargoCommand {
    pub fn new(value: impl Into<String>) -> Result<Self, RemoteValidationError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(RemoteValidationError::Empty { field: "cargo command" });
        }
        if value.split_whitespace().count() != 1 {
            return Err(RemoteValidationError::Whitespace { field: "cargo command", value });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Environment-variable prefix applied to the remote `cargo` invocation
/// (e.g. `RUST_BACKTRACE=1`). May be empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BuildEnv(String);

impl BuildEnv {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A path synced to the remote *in addition to* the project tree — e.g. a prebuilt `.so`,
/// static lib, or header dir that a `build.rs` links against. Configured per-remote.
///
/// Extras are synced incrementally but are **not pruned**, and live outside the project's
/// build dir, so they never interfere with cargo's source sync or `target/` cache. Reference
/// them from the build via `RUSTFLAGS` (e.g. `-L native=$HOME/<remote>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraPath {
    /// Local file or directory (absolute, or relative to where `rustle` is invoked).
    pub local: PathBuf,
    /// Destination on the remote: relative to the login home dir, or an absolute path.
    pub remote: String,
}

/// How to verify the remote's SSH host key against `~/.ssh/known_hosts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HostKeyCheck {
    /// Verify against `known_hosts`; record the key for a not-yet-known host on first connect;
    /// **reject** a host whose key has changed (the MITM case). Like OpenSSH `accept-new`.
    #[default]
    AcceptNew,
    /// Verify against `known_hosts`; reject any host not already present (no auto-recording).
    Strict,
    /// Skip host-key verification. Insecure — only for trusted networks / throwaway hosts.
    AcceptAll,
}

impl HostKeyCheck {
    pub fn as_str(self) -> &'static str {
        match self {
            HostKeyCheck::AcceptNew => "accept-new",
            HostKeyCheck::Strict => "strict",
            HostKeyCheck::AcceptAll => "accept-all",
        }
    }

    /// Parse a config/argument value; `None` if unrecognised.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "accept-new" => Some(HostKeyCheck::AcceptNew),
            "strict" => Some(HostKeyCheck::Strict),
            "accept-all" => Some(HostKeyCheck::AcceptAll),
            _ => None,
        }
    }
}

/// A fully-resolved remote build host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    pub name: Option<RemoteName>,
    pub host: Host,
    /// SSH username, when not embedded in `host` as `user@host`. An explicit value here wins
    /// over any `user@` in `host`.
    pub user: Option<String>,
    pub port: Port,
    pub temp_dir: RemoteDir,
    pub env: EnvProfile,
    /// How to verify this host's SSH key.
    pub host_key_check: HostKeyCheck,
    /// Optional shell command run on the remote just before the build (in the project dir,
    /// same shell — so its `export`s reach cargo). Lets the user shape the remote environment
    /// from config: install packages, export vars, `ldconfig`, run a script, etc.
    pub setup: Option<String>,
    /// Extra local paths to sync to the remote for this host (see [`ExtraPath`]).
    pub extra_paths: Vec<ExtraPath>,
}

/// Which crates of the project to build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetSelection {
    /// Cargo's default behaviour at the given manifest (no extra selection flag).
    Default,
    /// `--workspace`: every member of the workspace.
    Workspace,
    /// `-p <name>`: a single package.
    Package(String),
}

impl TargetSelection {
    /// The extra cargo selection arguments this selection contributes.
    pub fn to_args(&self) -> Vec<String> {
        match self {
            TargetSelection::Default => Vec::new(),
            TargetSelection::Workspace => vec!["--workspace".to_string()],
            TargetSelection::Package(name) => vec!["-p".to_string(), name.clone()],
        }
    }
}

/// What, if anything, to copy back from the remote `target/` directory after a build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopyBack {
    /// Copy nothing back.
    None,
    /// Copy the entire `target/` directory back.
    Target,
    /// Copy a specific path within `target/` back.
    Path(String),
}

/// The validated request to perform a remote build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildRequest {
    /// Local path to the `Cargo.toml` that anchors the project.
    pub manifest_path: PathBuf,
    pub selection: TargetSelection,
    pub command: CargoCommand,
    /// Extra cargo arguments/flags applied after the command and selection.
    pub options: Vec<String>,
    pub build_env: BuildEnv,
    pub toolchain: Toolchain,
    pub copy_back: CopyBack,
    /// Whether to copy the resolved `Cargo.lock` back to the client.
    pub copy_lock: bool,
    /// Whether to transfer hidden files/directories to the remote.
    pub transfer_hidden: bool,
    /// How to handle the remote command's output (stream vs capture).
    pub output: OutputMode,
}

/// Optional per-invocation overrides for a remote, sourced from CLI flags / MCP args. Each
/// `Some` value replaces the corresponding config value. Every config field is representable
/// here so the CLI and MCP expose the same knobs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemoteOverrides {
    pub host: Option<Host>,
    pub user: Option<String>,
    pub port: Option<Port>,
    pub temp_dir: Option<RemoteDir>,
    pub env: Option<EnvProfile>,
    pub host_key_check: Option<HostKeyCheck>,
    pub setup: Option<String>,
    pub extra_paths: Option<Vec<ExtraPath>>,
}

/// How a caller selects (and optionally overrides) which remote to build on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemoteSelector {
    /// Select a named remote from config; `None` means "the default/first remote".
    pub name: Option<RemoteName>,
    /// Per-invocation overrides layered on top of the selected remote.
    pub overrides: RemoteOverrides,
}

/// A single cargo package discovered in the project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageInfo {
    pub name: String,
    pub manifest_path: PathBuf,
}

/// Resolved information about the local cargo project / workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceInfo {
    /// The workspace root (the directory whose contents are synced to the remote).
    pub root: PathBuf,
    pub packages: Vec<PackageInfo>,
}

/// How a remote command's output should be handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    /// Inherit the parent stdio (live streaming to the terminal); output is not captured.
    Inherit,
    /// Capture stdout/stderr into the returned [`CommandOutput`].
    Capture,
}

/// A shell command line to execute on the remote host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteCommand {
    pub line: String,
}

/// The result of running a remote command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub exit_code: i32,
    /// Captured stdout (empty under [`OutputMode::Inherit`]).
    pub stdout: String,
    /// Captured stderr (empty under [`OutputMode::Inherit`]).
    pub stderr: String,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

/// A plan describing how to push the local source tree to the remote build dir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferPlan {
    /// Local workspace root to sync from.
    pub local_root: PathBuf,
    /// Absolute (or `~`-relative) remote build directory to sync into.
    pub build_path: String,
    /// Relative paths (from `local_root`) never to transfer. Always includes `target`.
    pub excludes: Vec<String>,
    /// Whether to include dotfiles / hidden directories.
    pub include_hidden: bool,
    /// Whether to prune remote files no longer present locally (like rsync `--delete`),
    /// while always preserving excluded paths such as `target/`.
    pub prune: bool,
    /// Extra paths to sync alongside the project tree (not pruned).
    pub extras: Vec<ExtraPath>,
    /// Per-project remote root for `extras`, *outside* the build dir (confined under the
    /// rustle temp dir). Each extra's `remote` is placed relative to this, and the build
    /// gets it as `$RUSTLE_EXTRA`.
    pub extra_root: String,
}

/// A single artifact to pull back from the remote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullItem {
    /// Path on the remote, relative to the build dir (e.g. `target/release/foo`).
    pub remote_rel: String,
    /// Destination path on the client, relative to the workspace root.
    pub local_rel: String,
}

/// A plan describing which artifacts to pull back from the remote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullPlan {
    pub local_root: PathBuf,
    pub build_path: String,
    pub items: Vec<PullItem>,
}

/// The outcome of a completed remote build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildOutcome {
    pub exit_code: i32,
    pub success: bool,
    /// Captured remote output (populated only when the executor ran in capture mode).
    pub stdout: String,
    pub stderr: String,
    /// Client-side paths that were copied back from the remote.
    pub copied_artifacts: Vec<PathBuf>,
}
