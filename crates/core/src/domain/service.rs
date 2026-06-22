//! The domain `Service`: the heart of the application.
//!
//! `Service` holds the four outbound ports as `Arc<dyn …>` trait objects and orchestrates them
//! to perform a remote build. It contains no knowledge of rsync, ssh, cargo_metadata or any
//! concrete adapter — only the ports. (The ports are dyn-compatible precisely because their
//! async methods return boxed futures.)

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::{Arc, Mutex};

use super::errors::{BuildError, ConfigError, MetadataError};
use super::models::{
    BuildOutcome, BuildRequest, CopyBack, PullItem, PullPlan, Remote, RemoteCommand,
    RemoteSelector, TransferPlan, WorkspaceInfo,
};
use super::ports::{
    PortFuture, ProjectMetadata, RemoteBuildService, RemoteExecutor, RemoteRepository,
    SourceTransfer,
};

/// Per-remote-build-dir locks: ensures two builds of the same project (same `build_path`)
/// can't interleave their push/prune/cargo/pull against one remote directory.
type BuildLocks = Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>;

/// Canonical implementation of [`RemoteBuildService`], composed from outbound port objects.
#[derive(Clone)]
pub struct Service {
    transfer: Arc<dyn SourceTransfer>,
    executor: Arc<dyn RemoteExecutor>,
    remotes: Arc<dyn RemoteRepository>,
    metadata: Arc<dyn ProjectMetadata>,
    build_locks: BuildLocks,
}

impl Service {
    pub fn new(
        transfer: Arc<dyn SourceTransfer>,
        executor: Arc<dyn RemoteExecutor>,
        remotes: Arc<dyn RemoteRepository>,
        metadata: Arc<dyn ProjectMetadata>,
    ) -> Self {
        Self {
            transfer,
            executor,
            remotes,
            metadata,
            build_locks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Acquire the serialization lock for a remote build dir, so concurrent builds of the same
    /// project (e.g. simultaneous MCP tool calls) run one-at-a-time instead of corrupting it.
    async fn lock_build_dir(&self, build_path: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.build_locks.lock().unwrap();
            locks
                .entry(build_path.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        lock.lock_owned().await
    }
}

/// Stable per-project hash used to key the remote build dir and extra store.
fn project_hash(root: &Path) -> u64 {
    let mut hasher = DefaultHasher::new();
    root.hash(&mut hasher);
    hasher.finish()
}

/// The per-project remote build path `<temp_dir>/<hash>/`, reused on every invocation so that
/// (a) source syncs are incremental and (b) the remote `target/` build cache stays warm.
fn build_path_for(remote: &Remote, hash: u64) -> String {
    format!("{}/{}/", remote.temp_dir.as_str(), hash)
}

/// The per-project remote extra store `<temp_dir>/extra/<hash>`, kept *outside* the build dir
/// (so the source sync never prunes it) and confined under the rustle temp dir (so it
/// never pollutes `$HOME`). Exposed to the build as `$RUSTLE_EXTRA`.
fn extra_root_for(remote: &Remote, hash: u64) -> String {
    format!("{}/extra/{}", remote.temp_dir.as_str(), hash)
}

/// Assemble the remote shell command line:
/// `source <env>; rustup default <tc>; cd <build_path>; export RUSTLE_EXTRA=<root>;
///  <setup>; <build_env> cargo <cmd> <sel> <opts>`.
fn build_command_line(
    req: &BuildRequest,
    remote: &Remote,
    build_path: &str,
    extra_root: &str,
) -> RemoteCommand {
    let mut cargo = format!("cargo {}", req.command.as_str());
    for arg in req.selection.to_args() {
        cargo.push(' ');
        cargo.push_str(&arg);
    }
    for opt in &req.options {
        cargo.push(' ');
        cargo.push_str(opt);
    }

    let build_env = req.build_env.as_str();
    let prefix = if build_env.is_empty() {
        String::new()
    } else {
        format!("{build_env} ")
    };

    // User-configured remote setup, run in the project dir before the build (same shell).
    let setup = match remote.setup.as_deref() {
        Some(setup) => format!("{setup}; "),
        None => String::new(),
    };

    // Expose the extra store to setup + build.rs + RUSTFLAGS as $RUSTLE_EXTRA. Unquoted
    // so a leading `~` in temp_dir expands in the assignment.
    let line = format!(
        "source {env}; rustup default {toolchain}; cd {path}; \
         export RUSTLE_EXTRA={extra_root}; {setup}{prefix}{cargo}",
        env = remote.env.as_str(),
        toolchain = req.toolchain.as_str(),
        path = build_path,
    );
    RemoteCommand { line }
}

/// Build the list of artifacts to pull back after a build.
fn pull_items(req: &BuildRequest) -> Vec<PullItem> {
    let mut items = Vec::new();
    match &req.copy_back {
        CopyBack::None => {}
        CopyBack::Target => items.push(PullItem {
            remote_rel: "target".to_string(),
            local_rel: "target".to_string(),
        }),
        CopyBack::Path(path) => items.push(PullItem {
            remote_rel: format!("target/{path}"),
            local_rel: format!("target/{path}"),
        }),
    }
    if req.copy_lock {
        items.push(PullItem {
            remote_rel: "Cargo.lock".to_string(),
            local_rel: "Cargo.lock".to_string(),
        });
    }
    items
}

impl RemoteBuildService for Service {
    fn build<'a>(
        &'a self,
        req: &'a BuildRequest,
        selector: &'a RemoteSelector,
    ) -> PortFuture<'a, Result<BuildOutcome, BuildError>> {
        Box::pin(async move {
        // 1. Resolve the concrete remote (config + CLI overrides).
        let remote = self.remotes.get(selector).await?.ok_or(BuildError::NoRemote)?;

        // 2. Resolve the workspace root (the directory we sync).
        let workspace = self.metadata.resolve(&req.manifest_path).await?;
        let root = workspace.root;
        tracing::info!(project_dir = %root.display(), "resolved workspace root");

        // 3. Stable, reused remote build path + per-project extra store.
        let hash = project_hash(&root);
        let build_path = build_path_for(&remote, hash);
        let extra_root = extra_root_for(&remote, hash);
        tracing::info!(build_path = %build_path, "remote build path");

        // Serialize against any other build targeting this same remote dir (held until done).
        let _build_guard = self.lock_build_dir(&build_path).await;

        // 4. Push sources (incremental; never touches the remote target/ cache).
        let mut excludes = vec!["target".to_string()];
        if !req.transfer_hidden {
            excludes.push(".*".to_string());
        }
        let push_plan = TransferPlan {
            local_root: root.clone(),
            build_path: build_path.clone(),
            excludes,
            include_hidden: req.transfer_hidden,
            prune: true,
            extras: remote.extra_paths.clone(),
            extra_root: extra_root.clone(),
        };
        tracing::info!("transferring sources to build server");
        self.transfer.push(&remote, &push_plan).await?;

        // 5. Run cargo on the remote.
        let command = build_command_line(req, &remote, &build_path, &extra_root);
        tracing::info!(command = %command.line, "starting remote build");
        let output = self.executor.run(&remote, &command, req.output).await?;

        // 6. Pull artifacts back (regardless of build exit status, matching the original).
        let items = pull_items(req);
        let copied_artifacts = if items.is_empty() {
            Vec::new()
        } else {
            let pull_plan = PullPlan {
                local_root: root.clone(),
                build_path: build_path.clone(),
                items,
            };
            tracing::info!("transferring artifacts back to client");
            self.transfer.pull(&remote, &pull_plan).await?
        };

        Ok(BuildOutcome {
            exit_code: output.exit_code,
            success: output.success(),
            stdout: output.stdout,
            stderr: output.stderr,
            copied_artifacts,
        })
        })
    }

    fn list_remotes(&self) -> PortFuture<'_, Result<Vec<Remote>, ConfigError>> {
        self.remotes.list()
    }

    fn resolve_workspace<'a>(
        &'a self,
        manifest_path: &'a Path,
    ) -> PortFuture<'a, Result<WorkspaceInfo, MetadataError>> {
        self.metadata.resolve(manifest_path)
    }
}
