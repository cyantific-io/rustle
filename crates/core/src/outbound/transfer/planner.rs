//! The push-planning seam.
//!
//! A [`RemotePlanner`] answers one question for the transfer adapter: *given the local source
//! manifest, what file contents must I upload?* — having already reconciled everything structural
//! on the remote (created the directories those uploads need, recreated changed symlinks, and
//! pruned extraneous entries). The transfer adapter then streams just those bytes over SFTP.
//!
//! Two implementations sit behind this port, chosen as `Arc<dyn RemotePlanner>`:
//! - the native SFTP planner (lists/diffs/prunes over the protocol — always works), and
//! - the agent planner (ships the manifest to a remote agent that does it all in one round-trip).
//!
//! This is an adapter-internal port: the domain `Service` never sees it.

use crate::domain::errors::TransferError;
use crate::domain::models::{Remote, TransferPlan};
use crate::domain::ports::PortFuture;

/// A regular file discovered in the local tree: path relative to the workspace root, the full
/// local path to read, and the quick-check keys (size + mtime, second granularity).
pub(crate) struct LocalFile {
    pub(crate) rel: String,
    pub(crate) full: std::path::PathBuf,
    pub(crate) len: u64,
    pub(crate) mtime: u32,
}

/// A local symlink to reproduce on the remote, its target carried verbatim (never followed).
pub(crate) struct LocalLink {
    pub(crate) rel: String,
    pub(crate) target: String,
}

/// The result of planning a push: the rel paths whose *contents* the caller must now upload
/// (their parent directories already created by the planner), plus counters for logging.
pub(crate) struct Worklist {
    pub(crate) uploads: Vec<String>,
    pub(crate) created_dirs: u32,
    pub(crate) pruned: u32,
    pub(crate) symlinks: u32,
}

/// Reconciles the remote build tree's structure against the local manifest and reports the files
/// the caller must upload. **Contract:** on success, every rel in `uploads` has its parent
/// directories present on the remote, symlinks are reconciled, and (when `plan.prune`) stale
/// entries are removed.
pub(crate) trait RemotePlanner: Send + Sync {
    fn plan<'a>(
        &'a self,
        remote: &'a Remote,
        plan: &'a TransferPlan,
        files: &'a [LocalFile],
        links: &'a [LocalLink],
    ) -> PortFuture<'a, Result<Worklist, TransferError>>;
}

/// How a push learns/reconciles remote state. Selected once at adapter construction (a global
/// client setting, like `--jobs`), surfaced identically on the CLI and the MCP server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SyncMode {
    /// Native SFTP listing + diff + prune. Always works; no remote footprint.
    Sftp,
    /// Deploy & drive the remote agent; fail loudly if it can't (no fallback).
    Agent,
    /// Prefer the agent; on any agent failure, warn and fall back to the SFTP path.
    #[default]
    Auto,
}

impl SyncMode {
    pub fn as_str(self) -> &'static str {
        match self {
            SyncMode::Sftp => "sftp",
            SyncMode::Agent => "agent",
            SyncMode::Auto => "auto",
        }
    }
}
