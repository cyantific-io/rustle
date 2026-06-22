//! Ports: the trait boundary between the domain and the outside world.
//!
//! The inbound port ([`RemoteBuildService`]) is what driving adapters (CLI, MCP) call. The
//! outbound ports are what the domain calls and adapters implement.
//!
//! Async methods return a strongly-typed boxed future ([`PortFuture`]) rather than RPITIT
//! (`impl Future`). This keeps every port **dyn-compatible** (usable behind `dyn Trait`) while
//! avoiding the `async_trait` macro entirely.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use super::errors::{BuildError, ConfigError, ExecError, MetadataError, TransferError};
use super::models::{
    BuildOutcome, BuildRequest, CommandOutput, OutputMode, PullPlan, Remote, RemoteCommand,
    RemoteSelector, TransferPlan, WorkspaceInfo,
};

/// A boxed, `Send` future returned by all async port methods. Borrowing `'a` lets the future
/// hold references to `&self` and the call's arguments.
pub type PortFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Inbound port: the canonical API for building cargo projects on remote hosts.
pub trait RemoteBuildService: Clone + Send + Sync + 'static {
    /// Build (or test/check/clippy/…) the project described by `req` on the selected remote.
    fn build<'a>(
        &'a self,
        req: &'a BuildRequest,
        remote: &'a RemoteSelector,
    ) -> PortFuture<'a, Result<BuildOutcome, BuildError>>;

    /// List every remote defined in the configuration.
    fn list_remotes(&self) -> PortFuture<'_, Result<Vec<Remote>, ConfigError>>;

    /// Resolve workspace information (root + member packages) for a local manifest.
    fn resolve_workspace<'a>(
        &'a self,
        manifest_path: &'a Path,
    ) -> PortFuture<'a, Result<WorkspaceInfo, MetadataError>>;
}

/// Outbound port: transfer source trees to, and artifacts from, a remote host.
pub trait SourceTransfer: Send + Sync + 'static {
    /// Push the local source tree to the remote build dir per `plan`.
    fn push<'a>(
        &'a self,
        remote: &'a Remote,
        plan: &'a TransferPlan,
    ) -> PortFuture<'a, Result<(), TransferError>>;

    /// Pull artifacts back from the remote per `plan`; returns the client paths written.
    fn pull<'a>(
        &'a self,
        remote: &'a Remote,
        plan: &'a PullPlan,
    ) -> PortFuture<'a, Result<Vec<PathBuf>, TransferError>>;
}

/// Outbound port: run a shell command on a remote host.
pub trait RemoteExecutor: Send + Sync + 'static {
    fn run<'a>(
        &'a self,
        remote: &'a Remote,
        command: &'a RemoteCommand,
        output: OutputMode,
    ) -> PortFuture<'a, Result<CommandOutput, ExecError>>;
}

/// Outbound port: a store of configured remote definitions.
pub trait RemoteRepository: Send + Sync + 'static {
    /// Resolve a concrete [`Remote`] from a selector, layering CLI overrides over config.
    fn get<'a>(
        &'a self,
        selector: &'a RemoteSelector,
    ) -> PortFuture<'a, Result<Option<Remote>, ConfigError>>;

    /// List every configured remote.
    fn list(&self) -> PortFuture<'_, Result<Vec<Remote>, ConfigError>>;
}

/// Outbound port: introspect a local cargo project.
pub trait ProjectMetadata: Send + Sync + 'static {
    fn resolve<'a>(
        &'a self,
        manifest_path: &'a Path,
    ) -> PortFuture<'a, Result<WorkspaceInfo, MetadataError>>;
}
