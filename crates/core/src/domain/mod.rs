//! The domain core: business logic, ports, models and errors. Depends on no adapter.

pub mod errors;
pub mod models;
pub mod ports;
pub mod service;

pub use errors::{
    enrollment_target, AgentError, BuildError, ConfigError, ExecError, MetadataError,
    RemoteValidationError, SshError, TransferError,
};
pub use models::{
    BuildEnv, BuildOutcome, BuildRequest, CargoCommand, CommandOutput, CopyBack, EnvProfile,
    ExtraPath, Host, HostKeyCheck, OutputMode, PackageInfo, Port, PullItem, PullPlan, Remote,
    RemoteCommand, RemoteDir, RemoteName, RemoteOverrides, RemoteSelector, TargetSelection,
    Toolchain, TransferPlan, WorkspaceInfo,
};
pub use ports::{
    PortFuture, ProjectMetadata, RemoteBuildService, RemoteExecutor, RemoteRepository,
    SourceTransfer,
};
pub use service::Service;
