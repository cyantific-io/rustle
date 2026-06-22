//! Cargo project introspection adapter, backed by the `cargo_metadata` crate.

use std::path::Path;

use crate::domain::errors::MetadataError;
use crate::domain::models::{PackageInfo, WorkspaceInfo};
use crate::domain::ports::{PortFuture, ProjectMetadata};

/// Resolves workspace info by invoking `cargo metadata` (with `--no-deps`).
#[derive(Debug, Clone, Default)]
pub struct CargoMetadataAdapter;

impl CargoMetadataAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl ProjectMetadata for CargoMetadataAdapter {
    fn resolve<'a>(
        &'a self,
        manifest_path: &'a Path,
    ) -> PortFuture<'a, Result<WorkspaceInfo, MetadataError>> {
        Box::pin(async move {
        let manifest = manifest_path.to_path_buf();
        let manifest_for_err = manifest.clone();

        // `cargo metadata` shells out and blocks; keep it off the async reactor.
        let metadata = tokio::task::spawn_blocking(move || {
            cargo_metadata::MetadataCommand::new()
                .manifest_path(&manifest)
                .no_deps()
                .exec()
        })
        .await
        .expect("cargo metadata task panicked")
        .map_err(|source| MetadataError::Cargo {
            manifest: manifest_for_err,
            source,
        })?;

        let root = metadata.workspace_root.clone().into_std_path_buf();
        let packages = metadata
            .packages
            .iter()
            .map(|p| PackageInfo {
                name: p.name.to_string(),
                manifest_path: p.manifest_path.clone().into_std_path_buf(),
            })
            .collect();

        Ok(WorkspaceInfo { root, packages })
        })
    }
}
