//! Source-transfer adapter implementing [`crate::domain::ports::SourceTransfer`].
//!
//! The transport is SFTP; *how a push is planned* (what to upload + reconciling remote structure)
//! is pluggable behind [`planner::RemotePlanner`] and selected by [`SyncMode`]:
//! - `sftp`  — list/diff/prune natively over SFTP (always works, no remote footprint),
//! - `agent` — deploy & drive the remote agent (one round-trip), failing loudly otherwise,
//! - `auto`  — prefer the agent, fall back (loudly) to SFTP.

use std::sync::Arc;

use crate::outbound::ssh::SshPool;

mod agent;
mod planner;
mod sftp;

pub use planner::SyncMode;
pub use sftp::{SftpTransfer, DEFAULT_CONCURRENCY};

use agent::AgentPlanner;
use planner::RemotePlanner;
use sftp::SftpPlanner;

/// Build the source-transfer adapter for the chosen [`SyncMode`], wiring up the planner (and, for
/// `auto`, the SFTP fallback). `main` calls this once at bootstrap.
pub fn build_transfer(mode: SyncMode, concurrency: usize, pool: Arc<SshPool>) -> SftpTransfer {
    let sftp_planner: Arc<dyn RemotePlanner> =
        Arc::new(SftpPlanner::new(concurrency, pool.clone()));
    let planner: Arc<dyn RemotePlanner> = match mode {
        SyncMode::Sftp => sftp_planner,
        SyncMode::Agent => Arc::new(AgentPlanner::new(pool.clone(), None)),
        SyncMode::Auto => Arc::new(AgentPlanner::new(pool.clone(), Some(sftp_planner))),
    };
    SftpTransfer::new(concurrency, pool, planner)
}
