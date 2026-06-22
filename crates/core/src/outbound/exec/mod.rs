//! Remote-execution adapter implementing [`crate::domain::ports::RemoteExecutor`].

mod ssh;
pub use ssh::SshExecutor;
