//! Outbound (driven) adapters: concrete implementations of the domain's outbound ports.

pub mod config;
pub mod exec;
pub mod metadata;
pub mod ssh;
pub mod transfer;

pub use config::FileRemoteRepository;
pub use exec::SshExecutor;
pub use metadata::CargoMetadataAdapter;
pub use ssh::SshPool;
pub use transfer::{build_transfer, SftpTransfer, SyncMode, DEFAULT_CONCURRENCY};
