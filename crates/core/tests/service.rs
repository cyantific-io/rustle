//! Unit tests for the domain `Service`, exercised against hand-rolled mock ports.
//!
//! Mocks implement the boxed-future ports directly (no `async_trait`, no mocking crate),
//! which also demonstrates that the ports are `dyn`-compatible.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use rustle_core::domain::{
    BuildEnv, BuildRequest, CargoCommand, CommandOutput, ConfigError, CopyBack, EnvProfile,
    ExecError, Host, HostKeyCheck, MetadataError, OutputMode, PortFuture, ProjectMetadata, PullPlan, Remote,
    RemoteCommand, RemoteDir, RemoteExecutor, RemoteRepository, RemoteSelector, Service, Port,
    TargetSelection, Toolchain, TransferError, TransferPlan, WorkspaceInfo,
};
use rustle_core::domain::{RemoteBuildService, SourceTransfer};

// --- Mocks ---------------------------------------------------------------------------------

#[derive(Clone, Default)]
struct MockTransfer {
    pushed: Arc<AtomicBool>,
    pulls: Arc<AtomicUsize>,
}

impl SourceTransfer for MockTransfer {
    fn push<'a>(
        &'a self,
        _remote: &'a Remote,
        _plan: &'a TransferPlan,
    ) -> PortFuture<'a, Result<(), TransferError>> {
        Box::pin(async move {
            self.pushed.store(true, Ordering::SeqCst);
            Ok(())
        })
    }

    fn pull<'a>(
        &'a self,
        _remote: &'a Remote,
        plan: &'a PullPlan,
    ) -> PortFuture<'a, Result<Vec<PathBuf>, TransferError>> {
        Box::pin(async move {
            self.pulls.fetch_add(1, Ordering::SeqCst);
            Ok(plan
                .items
                .iter()
                .map(|i| plan.local_root.join(&i.local_rel))
                .collect())
        })
    }
}

#[derive(Clone)]
struct MockExecutor {
    exit_code: i32,
}

impl RemoteExecutor for MockExecutor {
    fn run<'a>(
        &'a self,
        _remote: &'a Remote,
        command: &'a RemoteCommand,
        _output: OutputMode,
    ) -> PortFuture<'a, Result<CommandOutput, ExecError>> {
        Box::pin(async move {
            Ok(CommandOutput {
                exit_code: self.exit_code,
                stdout: command.line.clone(),
                stderr: String::new(),
            })
        })
    }
}

#[derive(Clone, Default)]
struct MockRemotes {
    remote: Option<Remote>,
}

impl RemoteRepository for MockRemotes {
    fn get<'a>(
        &'a self,
        _selector: &'a RemoteSelector,
    ) -> PortFuture<'a, Result<Option<Remote>, ConfigError>> {
        Box::pin(async move { Ok(self.remote.clone()) })
    }

    fn list(&self) -> PortFuture<'_, Result<Vec<Remote>, ConfigError>> {
        Box::pin(async move { Ok(self.remote.clone().into_iter().collect()) })
    }
}

#[derive(Clone)]
struct MockMetadata {
    root: PathBuf,
}

impl ProjectMetadata for MockMetadata {
    fn resolve<'a>(
        &'a self,
        _manifest_path: &'a Path,
    ) -> PortFuture<'a, Result<WorkspaceInfo, MetadataError>> {
        let root = self.root.clone();
        Box::pin(async move {
            Ok(WorkspaceInfo {
                root,
                packages: Vec::new(),
            })
        })
    }
}

// --- Helpers -------------------------------------------------------------------------------

fn test_remote() -> Remote {
    Remote {
        name: None,
        host: Host::new("user@host").unwrap(),
        user: None,
        port: Port::default(),
        temp_dir: RemoteDir::new("~/remote-builds").unwrap(),
        env: EnvProfile::new("/etc/profile").unwrap(),
        host_key_check: HostKeyCheck::AcceptAll,
        setup: None,
        extra_paths: Vec::new(),
    }
}

fn request(copy_back: CopyBack, copy_lock: bool) -> BuildRequest {
    BuildRequest {
        manifest_path: PathBuf::from("Cargo.toml"),
        selection: TargetSelection::Default,
        command: CargoCommand::new("build").unwrap(),
        options: vec!["--release".to_string()],
        build_env: BuildEnv::new("RUST_BACKTRACE=1"),
        toolchain: Toolchain::default(),
        copy_back,
        copy_lock,
        transfer_hidden: false,
        output: OutputMode::Capture,
    }
}

fn service(exit_code: i32, remote: Option<Remote>) -> (Service, MockTransfer) {
    let transfer = MockTransfer::default();
    // Compose the Service from `Arc<dyn …>` trait objects (the whole point of boxed futures).
    let svc = Service::new(
        Arc::new(transfer.clone()),
        Arc::new(MockExecutor { exit_code }),
        Arc::new(MockRemotes { remote }),
        Arc::new(MockMetadata {
            root: PathBuf::from("/tmp/project"),
        }),
    );
    (svc, transfer)
}

// --- Tests ---------------------------------------------------------------------------------

#[tokio::test]
async fn build_happy_path_pushes_and_succeeds() {
    let (svc, transfer) = service(0, Some(test_remote()));
    let outcome = svc
        .build(&request(CopyBack::None, false), &RemoteSelector::default())
        .await
        .expect("build should succeed");

    assert!(outcome.success);
    assert_eq!(outcome.exit_code, 0);
    assert!(transfer.pushed.load(Ordering::SeqCst), "sources must be pushed");
    assert_eq!(transfer.pulls.load(Ordering::SeqCst), 0, "no copy-back requested");
    // The remote command must carry the cargo command + options.
    assert!(outcome.stdout.contains("cargo build --release"));
}

#[tokio::test]
async fn build_propagates_nonzero_exit_as_outcome_not_error() {
    let (svc, _t) = service(101, Some(test_remote()));
    let outcome = svc
        .build(&request(CopyBack::None, false), &RemoteSelector::default())
        .await
        .expect("a failing cargo build is a valid outcome, not a service error");
    assert!(!outcome.success);
    assert_eq!(outcome.exit_code, 101);
}

#[tokio::test]
async fn build_without_remote_errors() {
    let (svc, _t) = service(0, None);
    let err = svc
        .build(&request(CopyBack::None, false), &RemoteSelector::default())
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        rustle_core::domain::BuildError::NoRemote
    ));
}

#[tokio::test]
async fn build_with_copy_back_and_lock_pulls_artifacts() {
    let (svc, transfer) = service(0, Some(test_remote()));
    let outcome = svc
        .build(&request(CopyBack::Target, true), &RemoteSelector::default())
        .await
        .expect("build should succeed");
    assert_eq!(transfer.pulls.load(Ordering::SeqCst), 1);
    // target + Cargo.lock => two artifacts copied back.
    assert_eq!(outcome.copied_artifacts.len(), 2);
}

#[tokio::test]
async fn extra_store_is_injected_under_temp_dir_not_home() {
    let (svc, _t) = service(0, Some(test_remote())); // temp_dir = ~/remote-builds
    let outcome = svc
        .build(&request(CopyBack::None, false), &RemoteSelector::default())
        .await
        .unwrap();
    // $RUSTLE_EXTRA points into the rustle temp dir's per-project store, never $HOME.
    assert!(
        outcome
            .stdout
            .contains("export RUSTLE_EXTRA=~/remote-builds/extra/"),
        "command was: {}",
        outcome.stdout
    );
}

#[tokio::test]
async fn setup_command_runs_before_build() {
    let mut remote = test_remote();
    remote.setup = Some("export PKG_CONFIG_PATH=/opt/foo".to_string());
    let (svc, _t) = service(0, Some(remote));
    // MockExecutor echoes the command line into stdout.
    let outcome = svc
        .build(&request(CopyBack::None, false), &RemoteSelector::default())
        .await
        .unwrap();
    let line = &outcome.stdout;
    let setup_at = line.find("export PKG_CONFIG_PATH=/opt/foo").expect("setup present");
    let cargo_at = line.find("cargo build").expect("cargo present");
    assert!(setup_at < cargo_at, "setup must precede the cargo invocation");
}

/// An executor that records peak in-flight concurrency, with a delay window so overlapping
/// builds would be observable if they weren't serialized.
#[derive(Clone)]
struct ConcurrencyExecutor {
    active: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

impl RemoteExecutor for ConcurrencyExecutor {
    fn run<'a>(
        &'a self,
        _remote: &'a Remote,
        _command: &'a RemoteCommand,
        _output: OutputMode,
    ) -> PortFuture<'a, Result<CommandOutput, ExecError>> {
        let active = self.active.clone();
        let peak = self.peak.clone();
        Box::pin(async move {
            let now = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            active.fetch_sub(1, Ordering::SeqCst);
            Ok(CommandOutput {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_builds_of_same_project_are_serialized() {
    let peak = Arc::new(AtomicUsize::new(0));
    let svc = Service::new(
        Arc::new(MockTransfer::default()),
        Arc::new(ConcurrencyExecutor {
            active: Arc::new(AtomicUsize::new(0)),
            peak: peak.clone(),
        }),
        Arc::new(MockRemotes {
            remote: Some(test_remote()),
        }),
        Arc::new(MockMetadata {
            root: PathBuf::from("/tmp/project"),
        }),
    );

    // Both builds resolve to the same project root → same build dir → must not overlap.
    let req = request(CopyBack::None, false);
    let sel = RemoteSelector::default();
    let (a, b) = tokio::join!(svc.build(&req, &sel), svc.build(&req, &sel));
    a.expect("build a");
    b.expect("build b");

    assert_eq!(
        peak.load(Ordering::SeqCst),
        1,
        "builds of the same project must be serialized, not run concurrently"
    );
}
