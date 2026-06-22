//! Config-file remote repository: loads remote definitions from a global `~/.cargo/rustle.toml`
//! and a project-local `.cargo/rustle.toml`, layering CLI overrides on top. Both live under
//! `.cargo/` to fit the cargo ecosystem (alongside `config.toml`).
//!
//! Config format:
//! ```toml
//! [[remote]]
//! name = "myRemote"        # optional
//! host = "user@server"     # required; user@host (ssh-config aliases are not resolved)
//! port = 42            # default 22
//! temp_dir = "~/rust"      # default "~/remote-builds"
//! env = "~/.profile"       # default "/etc/profile"
//! ```

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::domain::errors::{ConfigError, RemoteValidationError};
use crate::domain::models::{
    EnvProfile, ExtraPath, Host, HostKeyCheck, Port, Remote, RemoteDir, RemoteName, RemoteSelector,
};
use crate::domain::ports::{PortFuture, RemoteRepository};

/// Wrap a newtype validation failure with the offending remote's name for context.
fn invalid_remote(name: &str, source: RemoteValidationError) -> ConfigError {
    ConfigError::Invalid {
        name: name.to_string(),
        source,
    }
}

/// Parse an optional `host_key_check` config value (blank → `None`).
fn parse_host_key_check(
    value: &Option<String>,
    ctx: &str,
) -> Result<Option<HostKeyCheck>, ConfigError> {
    match value.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) => HostKeyCheck::parse(s).map(Some).ok_or_else(|| {
            invalid_remote(
                ctx,
                RemoteValidationError::InvalidHostKeyCheck {
                    value: s.to_string(),
                },
            )
        }),
    }
}

/// Build validated [`ExtraPath`]s from config entries.
fn build_extras(
    partials: &Option<Vec<PartialExtraPath>>,
    ctx: &str,
) -> Result<Vec<ExtraPath>, ConfigError> {
    let Some(partials) = partials else {
        return Ok(Vec::new());
    };
    partials
        .iter()
        .map(|p| {
            if p.local.trim().is_empty() {
                return Err(invalid_remote(ctx, RemoteValidationError::Empty { field: "extra_paths.local" }));
            }
            if p.remote.trim().is_empty() {
                return Err(invalid_remote(ctx, RemoteValidationError::Empty { field: "extra_paths.remote" }));
            }
            Ok(ExtraPath {
                local: PathBuf::from(&p.local),
                remote: p.remote.clone(),
            })
        })
        .collect()
}

const DEFAULT_TEMP_DIR: &str = "~/remote-builds";
const DEFAULT_ENV: &str = "/etc/profile";
/// Project-local config, searched up the directory tree (like cargo's own `.cargo/config.toml`).
const PROJECT_CONFIG: &str = ".cargo/rustle.toml";

/// Loads remotes from config files starting at a given directory.
#[derive(Debug, Clone)]
pub struct FileRemoteRepository {
    /// Directory to begin searching for a project-local `.cargo/rustle.toml` (walks ancestors).
    start_dir: PathBuf,
}

#[derive(Debug, Default, Deserialize)]
struct ConfigFile {
    #[serde(default)]
    remote: Vec<PartialRemote>,
}

#[derive(Debug, Clone, Deserialize)]
struct PartialRemote {
    name: Option<String>,
    host: String,
    user: Option<String>,
    port: Option<u16>,
    temp_dir: Option<String>,
    env: Option<String>,
    host_key_check: Option<String>,
    setup: Option<String>,
    extra_paths: Option<Vec<PartialExtraPath>>,
}

/// Treat an absent or whitespace-only setup command as "no setup".
fn clean_setup(setup: &Option<String>) -> Option<String> {
    setup
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[derive(Debug, Clone, Deserialize)]
struct PartialExtraPath {
    local: String,
    remote: String,
}

impl FileRemoteRepository {
    pub fn new(start_dir: impl Into<PathBuf>) -> Self {
        Self {
            start_dir: start_dir.into(),
        }
    }

    /// Global config at `~/.cargo/rustle.toml` (parallel to cargo's `~/.cargo/config.toml`).
    fn global_config_path() -> Option<PathBuf> {
        dirs::home_dir().map(|home| home.join(".cargo").join("remote.toml"))
    }

    fn project_config_path(&self) -> Option<PathBuf> {
        self.start_dir
            .ancestors()
            .map(|dir| dir.join(PROJECT_CONFIG))
            .find(|candidate| candidate.is_file())
    }

    fn parse_file(path: &Path) -> Result<Vec<PartialRemote>, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let parsed: ConfigFile = toml::from_str(&contents).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(parsed.remote)
    }

    /// Load the effective remote list. A project-local config, if present, takes precedence
    /// over the global config (matching the original array-replacement merge semantics).
    fn load(&self) -> Result<Vec<PartialRemote>, ConfigError> {
        let mut remotes = Vec::new();
        if let Some(global) = Self::global_config_path() {
            if global.is_file() {
                remotes = Self::parse_file(&global)?;
            }
        }
        if let Some(project) = self.project_config_path() {
            remotes = Self::parse_file(&project)?;
        }
        Ok(remotes)
    }

    /// Build a fully-defaulted [`Remote`] from a config entry (no CLI overrides).
    fn to_remote(partial: &PartialRemote) -> Result<Remote, ConfigError> {
        let name = partial.name.clone().unwrap_or_default();
        Ok(Remote {
            name: match &partial.name {
                Some(n) => Some(RemoteName::new(n.clone()).map_err(|e| invalid_remote(&name, e))?),
                None => None,
            },
            host: Host::new(partial.host.clone()).map_err(|e| invalid_remote(&name, e))?,
            user: partial.user.clone().filter(|u| !u.trim().is_empty()),
            port: match partial.port {
                Some(p) => Port::new(p).map_err(|e| invalid_remote(&name, e))?,
                None => Port::default(),
            },
            temp_dir: RemoteDir::new(
                partial
                    .temp_dir
                    .clone()
                    .unwrap_or_else(|| DEFAULT_TEMP_DIR.to_string()),
            )
            .map_err(|e| invalid_remote(&name, e))?,
            env: EnvProfile::new(
                partial
                    .env
                    .clone()
                    .unwrap_or_else(|| DEFAULT_ENV.to_string()),
            )
            .map_err(|e| invalid_remote(&name, e))?,
            host_key_check: parse_host_key_check(&partial.host_key_check, &name)?.unwrap_or_default(),
            setup: clean_setup(&partial.setup),
            extra_paths: build_extras(&partial.extra_paths, &name)?,
        })
    }
}

impl RemoteRepository for FileRemoteRepository {
    fn get<'a>(
        &'a self,
        selector: &'a RemoteSelector,
    ) -> PortFuture<'a, Result<Option<Remote>, ConfigError>> {
        Box::pin(async move {
        let remotes = self.load()?;
        let chosen: Option<&PartialRemote> = match &selector.name {
            Some(name) => remotes
                .iter()
                .find(|r| r.name.as_deref() == Some(name.as_str())),
            None => remotes.first(),
        };

        let ctx = chosen
            .and_then(|c| c.name.clone())
            .or_else(|| selector.name.as_ref().map(|n| n.to_string()))
            .unwrap_or_default();

        // With no config match and no inline host: a named remote is an explicit error,
        // while "the default remote" simply being absent yields None (→ NoRemote).
        if chosen.is_none() && selector.overrides.host.is_none() {
            return match &selector.name {
                Some(name) => Err(ConfigError::NotFound {
                    name: name.to_string(),
                }),
                None => Ok(None),
            };
        }

        // Host: CLI override wins, else config; with neither there is no usable remote.
        let host = if let Some(host) = selector.overrides.host.clone() {
            host
        } else if let Some(c) = chosen {
            Host::new(c.host.clone()).map_err(|e| invalid_remote(&ctx, e))?
        } else {
            return Ok(None);
        };

        let port = if let Some(port) = selector.overrides.port {
            port
        } else if let Some(port) = chosen.and_then(|c| c.port) {
            Port::new(port).map_err(|e| invalid_remote(&ctx, e))?
        } else {
            Port::default()
        };

        let temp_dir = if let Some(dir) = selector.overrides.temp_dir.clone() {
            dir
        } else if let Some(dir) = chosen.and_then(|c| c.temp_dir.clone()) {
            RemoteDir::new(dir).map_err(|e| invalid_remote(&ctx, e))?
        } else {
            RemoteDir::new(DEFAULT_TEMP_DIR).map_err(|e| invalid_remote(&ctx, e))?
        };

        let env = if let Some(env) = selector.overrides.env.clone() {
            env
        } else if let Some(env) = chosen.and_then(|c| c.env.clone()) {
            EnvProfile::new(env).map_err(|e| invalid_remote(&ctx, e))?
        } else {
            EnvProfile::new(DEFAULT_ENV).map_err(|e| invalid_remote(&ctx, e))?
        };

        let name = match &selector.name {
            Some(n) => Some(n.clone()),
            None => match chosen.and_then(|c| c.name.clone()) {
                Some(n) => Some(RemoteName::new(n).map_err(|e| invalid_remote(&ctx, e))?),
                None => None,
            },
        };

        let user = selector
            .overrides
            .user
            .clone()
            .or_else(|| chosen.and_then(|c| c.user.clone()))
            .filter(|u| !u.trim().is_empty());

        let setup = selector
            .overrides
            .setup
            .clone()
            .or_else(|| chosen.and_then(|c| c.setup.clone()))
            .and_then(|s| clean_setup(&Some(s)));

        let extra_paths = match &selector.overrides.extra_paths {
            Some(extras) => extras.clone(),
            None => match chosen {
                Some(c) => build_extras(&c.extra_paths, &ctx)?,
                None => Vec::new(),
            },
        };

        let host_key_check = match selector.overrides.host_key_check {
            Some(policy) => policy,
            None => parse_host_key_check(&chosen.and_then(|c| c.host_key_check.clone()), &ctx)?
                .unwrap_or_default(),
        };

        Ok(Some(Remote {
            name,
            host,
            user,
            port,
            temp_dir,
            env,
            host_key_check,
            setup,
            extra_paths,
        }))
        })
    }

    fn list(&self) -> PortFuture<'_, Result<Vec<Remote>, ConfigError>> {
        Box::pin(async move {
            self.load()?
                .iter()
                .map(Self::to_remote)
                .collect::<Result<Vec<_>, _>>()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml: &str) -> ConfigFile {
        toml::from_str(toml).expect("config should parse")
    }

    #[test]
    fn parses_extra_paths() {
        let cfg = parse(
            r#"
            [[remote]]
            name = "build"
            host = "user@host"
            extra_paths = [
              { local = "/opt/foo/lib", remote = "vendor/foo" },
              { local = "libbar.so", remote = "vendor/libbar.so" },
            ]
            "#,
        );
        let remote = FileRemoteRepository::to_remote(&cfg.remote[0]).unwrap();
        assert_eq!(remote.extra_paths.len(), 2);
        assert_eq!(remote.extra_paths[0].local, std::path::PathBuf::from("/opt/foo/lib"));
        assert_eq!(remote.extra_paths[0].remote, "vendor/foo");
        assert_eq!(remote.extra_paths[1].remote, "vendor/libbar.so");
    }

    #[test]
    fn parses_setup_and_blanks_become_none() {
        let cfg = parse(
            r#"
            [[remote]]
            host = "user@host"
            setup = "export PKG_CONFIG_PATH=/opt/foo/lib/pkgconfig"
            "#,
        );
        let remote = FileRemoteRepository::to_remote(&cfg.remote[0]).unwrap();
        assert_eq!(
            remote.setup.as_deref(),
            Some("export PKG_CONFIG_PATH=/opt/foo/lib/pkgconfig")
        );

        let blank = parse("[[remote]]\nhost = \"u@h\"\nsetup = \"   \"\n");
        assert!(FileRemoteRepository::to_remote(&blank.remote[0])
            .unwrap()
            .setup
            .is_none());
    }

    #[test]
    fn parses_host_key_check_and_defaults_to_accept_new() {
        let cfg = parse(
            "[[remote]]\nhost = \"u@h\"\nhost_key_check = \"strict\"\n",
        );
        assert_eq!(
            FileRemoteRepository::to_remote(&cfg.remote[0]).unwrap().host_key_check,
            HostKeyCheck::Strict
        );

        let default = parse("[[remote]]\nhost = \"u@h\"\n");
        assert_eq!(
            FileRemoteRepository::to_remote(&default.remote[0]).unwrap().host_key_check,
            HostKeyCheck::AcceptNew
        );

        let bad = parse("[[remote]]\nhost = \"u@h\"\nhost_key_check = \"bogus\"\n");
        assert!(FileRemoteRepository::to_remote(&bad.remote[0]).is_err());
    }

    #[test]
    fn no_extra_paths_is_empty() {
        let cfg = parse(
            r#"
            [[remote]]
            host = "user@host"
            "#,
        );
        let remote = FileRemoteRepository::to_remote(&cfg.remote[0]).unwrap();
        assert!(remote.extra_paths.is_empty());
    }

    #[test]
    fn empty_extra_field_is_rejected() {
        let cfg = parse(
            r#"
            [[remote]]
            host = "user@host"
            extra_paths = [{ local = "", remote = "x" }]
            "#,
        );
        assert!(FileRemoteRepository::to_remote(&cfg.remote[0]).is_err());
    }
}
