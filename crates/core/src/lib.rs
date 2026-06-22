//! `rustle-core`: hexagonal core for building Rust projects on remote hosts.
//!
//! - [`domain`] holds the business logic: validated models, ports (traits) and the
//!   orchestrating [`domain::Service`].
//! - [`outbound`] holds the driven adapters that implement the outbound ports (rsync/ssh
//!   transfer + execution, config loading, cargo metadata, and the librsync backend).
//!
//! Inbound adapters (the CLI and MCP server) live in their own crates and drive this core
//! through [`domain::RemoteBuildService`].

pub mod domain;
pub mod outbound;
