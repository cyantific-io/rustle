//! `cargo-rustle` CLI binary. `main` only bootstraps: parse args → build adapters → inject
//! into the domain `Service` → run → map the outcome to a process exit code. It also handles the
//! one interactive concern that belongs in the inbound layer: key **enrollment** (a pure-Rust
//! `ssh-copy-id`), offered automatically when a host isn't set up for passwordless auth yet.

mod cli;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::Arc;

use clap::Parser;
use tracing::error;
use tracing_subscriber::EnvFilter;

use rustle_core::domain::{
    enrollment_target, Remote, RemoteBuildService, RemoteRepository, Service, SshError,
};
use rustle_core::outbound::{
    build_transfer, CargoMetadataAdapter, FileRemoteRepository, SshExecutor, SshPool,
};

use cli::{Cargo, LogLevel};

#[tokio::main]
async fn main() {
    let Cargo::Rustle(args) = Cargo::parse();
    init_tracing(args.log_level());
    let jobs = args.jobs();
    let sync_mode = args.sync_mode();
    let setup_key = args.is_setup_key();
    let identity = args.identity();

    let (request, selector) = match args.into_domain() {
        Ok(parsed) => parsed,
        Err(e) => {
            log_error_chain(&e);
            exit(2);
        }
    };

    // Search for a project-local `.cargo/rustle.toml` starting from the manifest's directory.
    let start_dir = request
        .manifest_path
        .parent()
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    // One pooled SSH connection, reused across this command's push → build → pull.
    let pool = Arc::new(SshPool::new());
    let repo = Arc::new(FileRemoteRepository::new(start_dir));

    // Resolve the concrete remote (needed for `setup-key` and for pre-flight enrollment).
    let remote = match repo.get(&selector).await {
        Ok(remote) => remote,
        Err(e) => {
            log_error_chain(&e);
            exit(2);
        }
    };

    // `cargo rustle setup-key`: enroll this machine's key and exit — no build.
    if setup_key {
        let Some(remote) = remote else {
            error!("no remote to enroll — pass -r <name>, or -H <host> -u <user> [-p <port>]");
            exit(2);
        };
        exit(match enroll(&pool, &remote, &identity, false, true).await {
            Ok(()) => 0,
            Err(()) => 1,
        });
    }

    // Pre-flight: if the host rejects key auth but offers a password, it just isn't enrolled —
    // offer to install the key (with confirmation), then proceed with the build.
    if let Some(remote) = &remote {
        if let Err(SshError::NotEnrolled { .. }) = pool.ensure_authenticated(remote).await {
            if enroll(&pool, remote, &identity, true, false).await.is_err() {
                exit(1);
            }
        }
    }

    let service = Service::new(
        Arc::new(build_transfer(sync_mode, jobs, pool.clone())),
        Arc::new(SshExecutor::new(pool)),
        repo,
        Arc::new(CargoMetadataAdapter::new()),
    );

    match service.build(&request, &selector).await {
        Ok(outcome) => exit(outcome.exit_code),
        Err(e) => {
            if let Some((user, host, port)) = enrollment_target(&e) {
                error!(
                    "{user}@{host}:{port} is not enrolled — run: \
                     cargo rustle setup-key -H {host} -u {user} -p {port}"
                );
            }
            log_error_chain(&e);
            exit(1);
        }
    }
}

/// Interactive key enrollment — the pure-Rust `ssh-copy-id`. `confirm` gates the install behind a
/// `[y/N]` prompt (used by auto-enrollment); `explicit` means the user ran `setup-key` directly,
/// so an already-enrolled host is reported as success rather than re-installed.
async fn enroll(
    pool: &SshPool,
    remote: &Remote,
    pubkey_path: &Path,
    confirm: bool,
    explicit: bool,
) -> Result<(), ()> {
    let host = remote.host.as_str();
    let user = remote.user.as_deref().unwrap_or("");
    let port = remote.port.get();

    if explicit && pool.ensure_authenticated(remote).await.is_ok() {
        eprintln!("Already enrolled — key auth already works for {host}.");
        return Ok(());
    }

    let pubkey = match std::fs::read_to_string(pubkey_path) {
        Ok(s) => s.trim().to_string(),
        Err(e) => {
            error!("cannot read public key {}: {e}", pubkey_path.display());
            return Err(());
        }
    };
    let (algo, comment) = describe_key(&pubkey);

    eprintln!("{user}@{host} is not enrolled for passwordless (key) auth.");
    eprintln!(
        "This installs your {algo} key{comment} ({}) into the remote's ~/.ssh/authorized_keys.",
        pubkey_path.display()
    );
    if confirm && !prompt_yes("Proceed?") {
        eprintln!("Aborted; no changes made.");
        return Err(());
    }

    // Read from the tty (works even if stdin is piped); password is never stored or logged.
    let password = match rpassword::prompt_password(format!("{user}@{host} password: ")) {
        Ok(p) => p,
        Err(e) => {
            error!("could not read the password ({e}).");
            error!(
                "Key enrollment needs an interactive terminal. Run it directly in your shell \
                 (not via an editor/agent): cargo rustle setup-key -H {host} -u {user} -p {port}"
            );
            return Err(());
        }
    };

    if let Err(e) = pool.enroll_key(remote, &password, &pubkey).await {
        error!("enrollment failed: {e}");
        log_error_chain(&e);
        return Err(());
    }
    match pool.ensure_authenticated(remote).await {
        Ok(()) => {
            eprintln!("✓ enrolled — key auth now works for {host}.");
            Ok(())
        }
        Err(e) => {
            error!("key installed but verification failed: {e}");
            Err(())
        }
    }
}

fn prompt_yes(question: &str) -> bool {
    eprint!("{question} [y/N] ");
    let _ = io::stderr().flush();
    let mut line = String::new();
    if io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim(), "y" | "Y" | "yes" | "Yes")
}

/// Split an OpenSSH public-key line into `(algorithm, " (comment)" | "")` for a clear consent
/// prompt that shows exactly which key is being installed.
fn describe_key(pubkey: &str) -> (String, String) {
    let mut parts = pubkey.splitn(3, ' ');
    let algo = parts.next().unwrap_or("ssh-key").to_string();
    let _blob = parts.next();
    let comment = parts
        .next()
        .map(|c| format!(" ({})", c.trim()))
        .filter(|c| c.len() > 3)
        .unwrap_or_default();
    (algo, comment)
}

fn init_tracing(level: LogLevel) {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(level.as_filter()))
        .with_writer(std::io::stderr)
        .without_time()
        .init();
}

/// Log an error and its full typed `source` chain.
fn log_error_chain(err: &dyn std::error::Error) {
    error!("{err}");
    let mut source = err.source();
    while let Some(cause) = source {
        error!("  caused by: {cause}");
        source = cause.source();
    }
}
