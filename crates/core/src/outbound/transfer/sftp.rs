//! Pure-Rust SFTP transfer adapter (over russh). Implements file-level incremental sync:
//! only changed/new files are uploaded, extraneous files are pruned, and `target/` (plus
//! hidden files unless requested) is never touched — so the remote build cache stays warm.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use futures::future::try_join_all;
use futures::stream::{StreamExt, TryStreamExt};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{FileAttributes, OpenFlags};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::sync::Semaphore;
use walkdir::WalkDir;

use crate::domain::errors::TransferError;
use crate::domain::models::{ExtraPath, PullPlan, Remote, TransferPlan};
use crate::domain::ports::{PortFuture, SourceTransfer};
use crate::outbound::ssh::{SharedConnection, SshPool};

use super::planner::{LocalFile, LocalLink, RemotePlanner, Worklist};

/// Default max in-flight file transfers over a single SFTP session. The session multiplexes
/// requests, so this overlaps network round-trips across files (the main throughput lever for
/// many small files) while bounding memory and outstanding requests. Tunable via `--jobs`.
pub const DEFAULT_CONCURRENCY: usize = 16;
/// Streaming copy buffer — large enough for efficient SFTP write packets.
const COPY_BUF_SIZE: usize = 64 * 1024;

/// Boxed future returned by the recursive remote-listing helpers (push side).
type ListFuture<'a> =
    Pin<Box<dyn std::future::Future<Output = Result<Vec<RemoteEntry>, TransferError>> + Send + 'a>>;
/// Boxed future returned by the recursive pull-discovery helpers.
type PairFuture<'a> =
    Pin<Box<dyn std::future::Future<Output = Result<Vec<PullEntry>, TransferError>> + Send + 'a>>;

/// Transfers sources/artifacts over SFTP on a pooled pure-Rust russh session. The *planning* of a
/// push (what to upload + reconciling remote structure) is delegated to a [`RemotePlanner`]
/// (native SFTP or the remote agent); this adapter then streams the resulting file bytes.
#[derive(Clone)]
pub struct SftpTransfer {
    /// Max in-flight file transfers.
    concurrency: usize,
    pool: Arc<SshPool>,
    planner: Arc<dyn RemotePlanner>,
}

impl SftpTransfer {
    pub(crate) fn new(
        concurrency: usize,
        pool: Arc<SshPool>,
        planner: Arc<dyn RemotePlanner>,
    ) -> Self {
        Self {
            concurrency: concurrency.max(1),
            pool,
            planner,
        }
    }
}

/// The native planner: lists the remote tree over SFTP, diffs it against the local manifest,
/// prunes, creates directories, and reconciles symlinks — all over the protocol. Always works on
/// any SFTP server, with no remote footprint. This is the default and the `auto`-mode fallback.
pub(super) struct SftpPlanner {
    concurrency: usize,
    pool: Arc<SshPool>,
}

impl SftpPlanner {
    pub(super) fn new(concurrency: usize, pool: Arc<SshPool>) -> Self {
        Self {
            concurrency: concurrency.max(1),
            pool,
        }
    }
}

impl RemotePlanner for SftpPlanner {
    fn plan<'a>(
        &'a self,
        remote: &'a Remote,
        plan: &'a TransferPlan,
        files: &'a [LocalFile],
        links: &'a [LocalLink],
    ) -> PortFuture<'a, Result<Worklist, TransferError>> {
        Box::pin(async move {
            let (_conn, sftp) = open_sftp(&self.pool, remote).await?;
            let base = sftp_base(&plan.build_path);
            let mut ensured = HashSet::new();
            ensure_dir(&sftp, &base, &mut ensured).await;

            // Authoritative native listing (structured readdir, traversed concurrently).
            let sem = Semaphore::new(self.concurrency);
            let (remote_files, remote_links) = split_remote(
                list_remote(
                    &sftp,
                    &base,
                    String::new(),
                    &plan.excludes,
                    plan.include_hidden,
                    &sem,
                )
                .await?,
            );
            seed_existing_dirs(remote_files.keys().chain(remote_links.keys()), &base, &mut ensured);

            // Files whose size+mtime differ (or are absent) need uploading; create their parents.
            let mut uploads = Vec::new();
            for f in files {
                let changed = match remote_files.get(&f.rel) {
                    Some((size, mtime)) => *size != f.len || *mtime != f.mtime,
                    None => true,
                };
                if changed {
                    let remote_path = join(&base, &f.rel);
                    if let Some(idx) = remote_path.rfind('/') {
                        ensure_dir(&sftp, &remote_path[..idx], &mut ensured).await;
                    }
                    uploads.push(f.rel.clone());
                }
            }

            let symlinks = links
                .iter()
                .filter(|l| remote_links.get(&l.rel).map(String::as_str) != Some(l.target.as_str()))
                .count() as u32;
            sync_links(&sftp, &base, links, &remote_links, &mut ensured).await?;

            let mut pruned = 0u32;
            if plan.prune {
                let local: HashSet<&str> = files
                    .iter()
                    .map(|f| f.rel.as_str())
                    .chain(links.iter().map(|l| l.rel.as_str()))
                    .collect();
                let stale: Vec<String> = remote_files
                    .keys()
                    .chain(remote_links.keys())
                    .filter(|rel| !local.contains(rel.as_str()))
                    .map(|rel| join(&base, rel))
                    .collect();
                pruned = stale.len() as u32;
                let sftp = &sftp;
                futures::stream::iter(stale)
                    .for_each_concurrent(self.concurrency, |path| async move {
                        let _ = sftp.remove_file(path).await;
                    })
                    .await;
            }

            Ok(Worklist {
                uploads,
                created_dirs: ensured.len() as u32,
                pruned,
                symlinks,
            })
        })
    }
}

/// A remote tree entry discovered while listing (for incremental diff + prune).
enum RemoteEntry {
    File { rel: String, size: u64, mtime: u32 },
    Symlink { rel: String, target: String },
}

/// A discovered pull item: a remote file to download, or a symlink to recreate locally.
enum PullEntry {
    File { remote: String, dest: PathBuf },
    Symlink { dest: PathBuf, target: String },
}

/// Write an executable file to the remote over SFTP (used to deploy the bundled agent binary):
/// the bytes plus mode `0o755`. Propagates flush errors so a partial write is never mistaken for
/// success.
pub(super) async fn write_remote_executable(
    sftp: &SftpSession,
    path: &str,
    bytes: &[u8],
) -> Result<(), TransferError> {
    let mut file = sftp.create(path).await.map_err(TransferError::Sftp)?;
    file.write_all(bytes).await.map_err(|source| TransferError::Io {
        path: PathBuf::from(path),
        source,
    })?;
    let _ = file
        .set_metadata(FileAttributes {
            size: None,
            uid: None,
            user: None,
            gid: None,
            group: None,
            permissions: Some(0o755),
            atime: None,
            mtime: None,
        })
        .await;
    file.flush().await.map_err(|source| TransferError::Io {
        path: PathBuf::from(path),
        source,
    })?;
    file.shutdown().await.ok();
    Ok(())
}

/// Open an SFTP session on a pooled connection; the returned connection keeps the underlying
/// session alive for as long as the `SftpSession` is used.
pub(super) async fn open_sftp(
    pool: &SshPool,
    remote: &Remote,
) -> Result<(SharedConnection, SftpSession), TransferError> {
    let conn = pool.connect(remote).await?;
    // Hold the connection lock only to open the channel.
    let channel = {
        let handle = conn.lock().await;
        handle
            .channel_open_session()
            .await
            .map_err(|e| TransferError::Ssh(e.into()))?
    };
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| TransferError::Ssh(e.into()))?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(TransferError::Sftp)?;
    Ok((conn, sftp))
}

/// SFTP paths are relative to the login dir (home), and `~` is NOT expanded — strip a leading
/// `~/` so `~/remote-builds/<hash>` becomes the home-relative `remote-builds/<hash>`.
pub(super) fn sftp_base(build_path: &str) -> String {
    let trimmed = build_path.trim_end_matches('/');
    trimmed
        .strip_prefix("~/")
        .or_else(|| trimmed.strip_prefix("~"))
        .unwrap_or(trimmed)
        .to_string()
}

pub(super) fn join(base: &str, rel: &str) -> String {
    if base.is_empty() {
        rel.to_string()
    } else if rel.is_empty() {
        base.to_string()
    } else {
        format!("{base}/{rel}")
    }
}

fn is_excluded(rel: &str, excludes: &[String], include_hidden: bool) -> bool {
    if !include_hidden && rel.split('/').any(|c| c.starts_with('.')) {
        return true;
    }
    for ex in excludes {
        if ex == ".*" {
            continue;
        }
        // `rel == ex` (the path itself) or `rel` is under `ex/` — without allocating `"{ex}/"`.
        if rel == ex
            || (rel.len() > ex.len()
                && rel.starts_with(ex.as_str())
                && rel.as_bytes()[ex.len()] == b'/')
        {
            return true;
        }
    }
    false
}

fn mtime_secs(metadata: &std::fs::Metadata) -> u32 {
    metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

/// Walk the local tree, collecting regular files and symlinks (the latter preserved as links,
/// not followed). Directories are implicit. `follow_links(false)` means a symlink — even to a
/// directory — is reported as a symlink and not descended into.
#[allow(clippy::type_complexity)]
fn walk_entries(
    root: &Path,
    excludes: &[String],
    include_hidden: bool,
) -> Result<(Vec<LocalFile>, Vec<LocalLink>), TransferError> {
    let mut files = Vec::new();
    let mut links = Vec::new();
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.map_err(TransferError::Walk)?;
        let file_type = entry.file_type();
        let rel = match entry.path().strip_prefix(root) {
            Ok(rel) => rel.to_string_lossy().replace('\\', "/"),
            Err(_) => continue,
        };
        if rel.is_empty() || is_excluded(&rel, excludes, include_hidden) {
            continue;
        }
        if file_type.is_symlink() {
            let target = std::fs::read_link(entry.path()).map_err(|source| TransferError::Io {
                path: entry.path().to_path_buf(),
                source,
            })?;
            links.push(LocalLink {
                rel,
                target: target.to_string_lossy().replace('\\', "/"),
            });
        } else if file_type.is_file() {
            let metadata = entry.path().metadata().map_err(|source| TransferError::Io {
                path: entry.path().to_path_buf(),
                source,
            })?;
            files.push(LocalFile {
                rel,
                full: entry.path().to_path_buf(),
                len: metadata.len(),
                mtime: mtime_secs(&metadata),
            });
        }
    }
    Ok((files, links))
}

/// Seed `ensured` with the directories that already exist remotely (derived from the listed
/// file/symlink paths), so a warm rebuild skips `create_dir` round-trips for them — only
/// genuinely new directories are created.
fn seed_existing_dirs<'a>(
    rels: impl Iterator<Item = &'a String>,
    base: &str,
    ensured: &mut HashSet<String>,
) {
    for rel in rels {
        let full = join(base, rel);
        for (i, b) in full.bytes().enumerate() {
            if b == b'/' {
                ensured.insert(full[..i].to_string());
            }
        }
    }
}

/// Recursively create a remote directory (SFTP `create_dir` is not recursive), skipping any
/// prefix already created or known to exist this session. `ensured` dedupes across all files in
/// one push, so a shared parent like `src/` is created once, not once per file.
pub(super) async fn ensure_dir(sftp: &SftpSession, dir: &str, ensured: &mut HashSet<String>) {
    if dir.is_empty() {
        return;
    }
    let mut prefix = String::new();
    for part in dir.split('/') {
        if part.is_empty() {
            continue;
        }
        if prefix.is_empty() {
            prefix = part.to_string();
        } else {
            prefix = format!("{prefix}/{part}");
        }
        if ensured.insert(prefix.clone()) {
            // Newly seen this session — create it (ignore "already exists").
            let _ = sftp.create_dir(prefix.clone()).await;
        }
    }
}

/// Recursively list remote files under `base` (relative paths → size+mtime), honouring the
/// given excludes. Subdirectories are traversed concurrently, bounded by `sem` so the total
/// number of in-flight `readdir`s stays capped. Uses `readdir` attributes directly — no extra
/// `stat` per entry.
fn list_remote<'a>(
    sftp: &'a SftpSession,
    base: &'a str,
    rel_prefix: String,
    excludes: &'a [String],
    include_hidden: bool,
    sem: &'a Semaphore,
) -> ListFuture<'a> {
    Box::pin(async move {
        let dir = join(base, &rel_prefix);
        let read_path = if dir.is_empty() { ".".to_string() } else { dir };
        let entries = {
            let _permit = sem.acquire().await.expect("transfer semaphore not closed");
            match sftp.read_dir(read_path).await {
                Ok(entries) => entries,
                Err(_) => return Ok(Vec::new()), // directory doesn't exist yet
            }
        };

        let mut out = Vec::new();
        let mut subdirs = Vec::new();
        for entry in entries {
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let rel = if rel_prefix.is_empty() {
                name
            } else {
                format!("{rel_prefix}/{name}")
            };
            if is_excluded(&rel, excludes, include_hidden) {
                continue;
            }
            let metadata = entry.metadata();
            if metadata.file_type().is_symlink() {
                // Read the link target (one round-trip; symlinks are rare).
                let _permit = sem.acquire().await.expect("transfer semaphore not closed");
                if let Ok(target) = sftp.read_link(join(base, &rel)).await {
                    out.push(RemoteEntry::Symlink { rel, target });
                }
            } else if metadata.is_dir() {
                subdirs.push(list_remote(sftp, base, rel, excludes, include_hidden, sem));
            } else {
                out.push(RemoteEntry::File {
                    rel,
                    size: metadata.size.unwrap_or(0),
                    mtime: metadata.mtime.unwrap_or(0),
                });
            }
        }

        for sub in try_join_all(subdirs).await? {
            out.extend(sub);
        }
        Ok(out)
    })
}

/// Split a remote listing into a files map (rel → size+mtime) and a symlinks map (rel → target).
fn split_remote(entries: Vec<RemoteEntry>) -> (HashMap<String, (u64, u32)>, HashMap<String, String>) {
    let mut files = HashMap::new();
    let mut links = HashMap::new();
    for entry in entries {
        match entry {
            RemoteEntry::File { rel, size, mtime } => {
                files.insert(rel, (size, mtime));
            }
            RemoteEntry::Symlink { rel, target } => {
                links.insert(rel, target);
            }
        }
    }
    (files, links)
}

/// Recreate on the remote any local symlink whose target differs from (or is absent in)
/// `existing`. Replaces whatever is currently at the path (file or stale link).
async fn sync_links(
    sftp: &SftpSession,
    base: &str,
    links: &[LocalLink],
    existing: &HashMap<String, String>,
    ensured: &mut HashSet<String>,
) -> Result<(), TransferError> {
    for link in links {
        if existing.get(&link.rel) == Some(&link.target) {
            continue; // already correct
        }
        let remote_path = join(base, &link.rel);
        if let Some(idx) = remote_path.rfind('/') {
            ensure_dir(sftp, &remote_path[..idx], ensured).await;
        }
        // Remove whatever's there (regular file or outdated symlink), then recreate the link.
        let _ = sftp.remove_file(remote_path.clone()).await;
        sftp.symlink(remote_path, link.target.clone())
            .await
            .map_err(TransferError::Sftp)?;
    }
    Ok(())
}

/// Upload every file whose size+mtime differs from (or is absent in) `existing`.
///
/// Two phases: (1) pre-create all needed parent directories sequentially (deduped via
/// `ensured`) so the concurrent phase never races on `create_dir`; (2) upload the changed
/// files with bounded concurrency, overlapping their network round-trips.
async fn sync_files(
    sftp: &SftpSession,
    base: &str,
    files: &[LocalFile],
    existing: &HashMap<String, (u64, u32)>,
    ensured: &mut HashSet<String>,
    concurrency: usize,
) -> Result<(), TransferError> {
    let changed: Vec<&LocalFile> = files
        .iter()
        .filter(|f| match existing.get(&f.rel) {
            Some((size, mtime)) => *size != f.len || *mtime != f.mtime,
            None => true,
        })
        .collect();

    // Phase 1: create parent directories once each (sequential — no concurrent races).
    for file in &changed {
        let remote_path = join(base, &file.rel);
        if let Some(idx) = remote_path.rfind('/') {
            ensure_dir(sftp, &remote_path[..idx], ensured).await;
        }
    }

    // Phase 2: upload concurrently. All directories already exist. Each job owns its inputs
    // so the spawned futures don't borrow the iterator item.
    let jobs: Vec<(PathBuf, String, u32)> = changed
        .iter()
        .map(|f| (f.full.clone(), join(base, &f.rel), f.mtime))
        .collect();
    futures::stream::iter(jobs.into_iter().map(move |(full, remote_path, mtime)| async move {
        upload_file(sftp, &full, &remote_path, mtime).await
    }))
    .buffer_unordered(concurrency)
    .try_collect::<Vec<()>>()
    .await?;
    Ok(())
}

/// Sync one configured extra path (file or directory) into the per-project extra store
/// (`extra_root` + the extra's `remote`, treated as store-relative). Incremental, not pruned,
/// and confined under the rustle temp dir — never the bare remote `$HOME`.
async fn sync_extra(
    sftp: &SftpSession,
    extra: &ExtraPath,
    extra_root: &str,
    concurrency: usize,
) -> Result<(), TransferError> {
    let dest = join(&sftp_base(extra_root), extra.remote.trim_start_matches('/'));
    let metadata = std::fs::metadata(&extra.local).map_err(|source| TransferError::Io {
        path: extra.local.clone(),
        source,
    })?;

    let mut ensured = HashSet::new();
    if metadata.is_dir() {
        ensure_dir(sftp, &dest, &mut ensured).await;
        let sem = Semaphore::new(concurrency);
        let (existing_files, existing_links) =
            split_remote(list_remote(sftp, &dest, String::new(), &[], true, &sem).await?);
        let (files, links) = walk_entries(&extra.local, &[], true)?;
        sync_files(sftp, &dest, &files, &existing_files, &mut ensured, concurrency).await?;
        sync_links(sftp, &dest, &links, &existing_links, &mut ensured).await?;
    } else {
        if let Some(idx) = dest.rfind('/') {
            ensure_dir(sftp, &dest[..idx], &mut ensured).await;
        }
        let mtime = mtime_secs(&metadata);
        if let Ok(remote) = sftp.metadata(dest.clone()).await {
            if remote.size == Some(metadata.len()) && remote.mtime == Some(mtime) {
                return Ok(());
            }
        }
        upload_file(sftp, &extra.local, &dest, mtime).await?;
    }
    Ok(())
}

async fn upload_file(
    sftp: &SftpSession,
    local: &Path,
    remote_path: &str,
    mtime: u32,
) -> Result<(), TransferError> {
    let source = tokio::fs::File::open(local).await.map_err(|source| TransferError::Io {
        path: local.to_path_buf(),
        source,
    })?;
    let mut reader = BufReader::with_capacity(COPY_BUF_SIZE, source);
    let mut file = sftp.create(remote_path).await.map_err(TransferError::Sftp)?;

    // Stream the file in bounded chunks (the SFTP File pipelines writes internally).
    tokio::io::copy_buf(&mut reader, &mut file).await.map_err(|source| TransferError::Io {
        path: PathBuf::from(remote_path),
        source,
    })?;
    // Propagate flush errors: a failed/partial write must NOT be recorded as success
    // (otherwise the mtime gets stamped and the next push skips re-uploading it).
    file.flush().await.map_err(|source| TransferError::Io {
        path: PathBuf::from(remote_path),
        source,
    })?;
    // Mirror the local mtime so the next push's quick-check can skip unchanged files.
    let _ = file
        .set_metadata(FileAttributes {
            size: None,
            uid: None,
            user: None,
            gid: None,
            group: None,
            permissions: None,
            atime: Some(mtime),
            mtime: Some(mtime),
        })
        .await;
    file.shutdown().await.ok();
    Ok(())
}

async fn download_file(
    sftp: &SftpSession,
    remote_path: &str,
    dest: &Path,
) -> Result<(), TransferError> {
    // `create_dir_all` is idempotent and safe to call from concurrent downloads.
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|source| TransferError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
    }
    let remote = sftp
        .open_with_flags(remote_path, OpenFlags::READ)
        .await
        .map_err(TransferError::Sftp)?;
    // Batch into large SFTP READs instead of many small ones.
    let mut reader = BufReader::with_capacity(COPY_BUF_SIZE, remote);
    let mut writer = tokio::fs::File::create(dest).await.map_err(|source| TransferError::Io {
        path: dest.to_path_buf(),
        source,
    })?;
    // Stream remote → local without buffering the whole file in memory.
    tokio::io::copy_buf(&mut reader, &mut writer).await.map_err(|source| TransferError::Io {
        path: dest.to_path_buf(),
        source,
    })?;
    writer.flush().await.map_err(|source| TransferError::Io {
        path: dest.to_path_buf(),
        source,
    })?;
    Ok(())
}

/// Discover a top-level pull target (file, directory, or symlink), producing the files to
/// download and the symlinks to recreate locally. The one `stat` here resolves the item's type;
/// the directory walk below reuses `readdir` attributes. Dir symlinks are not followed, so a
/// cycle in `target/` cannot cause unbounded recursion.
fn collect_item<'a>(
    sftp: &'a SftpSession,
    remote_path: String,
    local_dest: PathBuf,
    sem: &'a Semaphore,
) -> PairFuture<'a> {
    Box::pin(async move {
        let metadata = {
            let _permit = sem.acquire().await.expect("transfer semaphore not closed");
            match sftp.symlink_metadata(remote_path.clone()).await {
                Ok(metadata) => metadata,
                Err(_) => return Ok(Vec::new()), // not present (e.g. build failed → no target/)
            }
        };
        if metadata.file_type().is_symlink() {
            let _permit = sem.acquire().await.expect("transfer semaphore not closed");
            match sftp.read_link(remote_path).await {
                Ok(target) => Ok(vec![PullEntry::Symlink {
                    dest: local_dest,
                    target,
                }]),
                Err(_) => Ok(Vec::new()),
            }
        } else if metadata.is_dir() {
            collect_dir(sftp, remote_path, local_dest, sem).await
        } else {
            Ok(vec![PullEntry::File {
                remote: remote_path,
                dest: local_dest,
            }])
        }
    })
}

/// Recursively list a remote directory (using `readdir` attributes, no per-entry `stat`),
/// traversing subdirectories concurrently within the `sem` budget. Symlinks are recorded (with
/// their target read) rather than followed.
fn collect_dir<'a>(
    sftp: &'a SftpSession,
    dir: String,
    local_dest: PathBuf,
    sem: &'a Semaphore,
) -> PairFuture<'a> {
    Box::pin(async move {
        let entries = {
            let _permit = sem.acquire().await.expect("transfer semaphore not closed");
            match sftp.read_dir(dir.clone()).await {
                Ok(entries) => entries,
                Err(_) => return Ok(Vec::new()),
            }
        };

        let mut out = Vec::new();
        let mut subdirs = Vec::new();
        for entry in entries {
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let metadata = entry.metadata();
            let child = format!("{dir}/{name}");
            let dest = local_dest.join(&name);
            if metadata.file_type().is_symlink() {
                let _permit = sem.acquire().await.expect("transfer semaphore not closed");
                if let Ok(target) = sftp.read_link(child).await {
                    out.push(PullEntry::Symlink { dest, target });
                }
            } else if metadata.is_dir() {
                subdirs.push(collect_dir(sftp, child, dest, sem));
            } else {
                out.push(PullEntry::File {
                    remote: child,
                    dest,
                });
            }
        }

        for sub in try_join_all(subdirs).await? {
            out.extend(sub);
        }
        Ok(out)
    })
}

/// Recreate a symlink locally (best-effort; replaces an existing entry at `dest`).
fn make_local_symlink(dest: &Path, target: &str) -> Result<(), TransferError> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|source| TransferError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let _ = std::fs::remove_file(dest);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, dest).map_err(|source| TransferError::Io {
            path: dest.to_path_buf(),
            source,
        })
    }
    #[cfg(not(unix))]
    {
        let _ = target;
        tracing::warn!(dest = %dest.display(), "skipping symlink (unsupported on this platform)");
        Ok(())
    }
}

impl SourceTransfer for SftpTransfer {
    fn push<'a>(
        &'a self,
        remote: &'a Remote,
        plan: &'a TransferPlan,
    ) -> PortFuture<'a, Result<(), TransferError>> {
        Box::pin(async move {
            let (_conn, sftp) = open_sftp(&self.pool, remote).await?;
            let base = sftp_base(&plan.build_path);

            // Ensure the build root exists before planning — both planners (and the upload below)
            // assume it's present; the agent in particular reconciles *under* it.
            let mut ensured = HashSet::new();
            ensure_dir(&sftp, &base, &mut ensured).await;

            let (local_files, local_links) =
                walk_entries(&plan.local_root, &plan.excludes, plan.include_hidden)?;

            // Reconcile remote structure (dirs/symlinks/prune) and learn what to upload. The
            // planner is either the native SFTP path or the one-round-trip remote agent.
            let worklist = self.planner.plan(remote, plan, &local_files, &local_links).await?;
            tracing::debug!(
                uploads = worklist.uploads.len(),
                created_dirs = worklist.created_dirs,
                pruned = worklist.pruned,
                symlinks = worklist.symlinks,
                "push reconciled remote tree"
            );

            // Stream just the changed file contents (their parent dirs already created above).
            let by_rel: HashMap<&str, &LocalFile> =
                local_files.iter().map(|f| (f.rel.as_str(), f)).collect();
            let jobs: Vec<(PathBuf, String, u32)> = worklist
                .uploads
                .iter()
                .filter_map(|rel| {
                    by_rel
                        .get(rel.as_str())
                        .map(|f| (f.full.clone(), join(&base, rel), f.mtime))
                })
                .collect();
            let sftp_ref = &sftp;
            futures::stream::iter(jobs.into_iter().map(move |(full, remote_path, mtime)| async move {
                upload_file(sftp_ref, &full, &remote_path, mtime).await
            }))
            .buffer_unordered(self.concurrency)
            .try_collect::<Vec<()>>()
            .await?;

            // Sync extra paths into the per-project extra store ($RUSTLE_EXTRA) — always
            // over SFTP (additive, never pruned), independent of the planner.
            for extra in &plan.extras {
                sync_extra(&sftp, extra, &plan.extra_root, self.concurrency).await?;
            }
            Ok(())
        })
    }

    fn pull<'a>(
        &'a self,
        remote: &'a Remote,
        plan: &'a PullPlan,
    ) -> PortFuture<'a, Result<Vec<PathBuf>, TransferError>> {
        Box::pin(async move {
            let (_conn, sftp) = open_sftp(&self.pool, remote).await?;
            let base = sftp_base(&plan.build_path);

            // Discover everything to pull (concurrent listing), then download concurrently.
            let sem = Semaphore::new(self.concurrency);
            let mut entries: Vec<PullEntry> = Vec::new();
            for item in &plan.items {
                let remote_path = join(&base, &item.remote_rel);
                let local_dest = plan.local_root.join(&item.local_rel);
                entries.extend(collect_item(&sftp, remote_path, local_dest, &sem).await?);
            }

            // Recreate symlinks locally (cheap, sequential), then download files concurrently.
            let mut copied = Vec::new();
            let mut downloads = Vec::new();
            for entry in entries {
                match entry {
                    PullEntry::Symlink { dest, target } => {
                        make_local_symlink(&dest, &target)?;
                        copied.push(dest);
                    }
                    PullEntry::File { remote, dest } => downloads.push((remote, dest)),
                }
            }

            let sftp = &sftp;
            let mut downloaded: Vec<PathBuf> = futures::stream::iter(downloads.into_iter().map(
                move |(remote, dest)| async move {
                    download_file(sftp, &remote, &dest).await?;
                    Ok::<PathBuf, TransferError>(dest)
                },
            ))
            .buffer_unordered(self.concurrency)
            .try_collect()
            .await?;
            copied.append(&mut downloaded);
            Ok(copied)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn excl() -> Vec<String> {
        vec!["target".to_string(), ".*".to_string()]
    }

    #[test]
    fn excludes_target_subtree_only_at_root() {
        assert!(is_excluded("target", &excl(), false));
        assert!(is_excluded("target/release/app", &excl(), false));
        // A different name that merely shares the prefix must NOT be excluded.
        assert!(!is_excluded("targetx", &excl(), false));
        assert!(!is_excluded("targetx/y", &excl(), false));
        // `target` nested under another dir is a different path — not excluded.
        assert!(!is_excluded("crates/target.rs", &excl(), false));
    }

    #[test]
    fn hidden_files_respect_include_flag() {
        assert!(is_excluded(".git/config", &excl(), false));
        assert!(is_excluded("src/.hidden", &excl(), false));
        assert!(!is_excluded(".git/config", &excl(), true));
        assert!(!is_excluded("src/main.rs", &excl(), false));
    }

    #[test]
    fn sftp_base_strips_home_relative_tilde() {
        assert_eq!(sftp_base("~/remote-builds/123/"), "remote-builds/123");
        assert_eq!(sftp_base("/abs/rust/123/"), "/abs/rust/123");
        assert_eq!(sftp_base("~"), "");
    }

    #[test]
    fn join_handles_empty_base() {
        assert_eq!(join("", "Cargo.lock"), "Cargo.lock");
        assert_eq!(join("remote-builds/1", "src/main.rs"), "remote-builds/1/src/main.rs");
        assert_eq!(join("base", ""), "base");
    }


    #[cfg(unix)]
    #[test]
    fn walk_entries_captures_symlinks_as_links_not_files() {
        let dir = std::env::temp_dir().join(format!("rustle-walk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/main.rs"), b"fn main() {}").unwrap();
        std::os::unix::fs::symlink("src/main.rs", dir.join("link.rs")).unwrap();

        let (files, links) = walk_entries(&dir, &[], false).unwrap();
        assert!(files.iter().any(|f| f.rel == "src/main.rs"));
        // The symlink is recorded as a link (with its target), NOT as a regular file.
        assert!(!files.iter().any(|f| f.rel == "link.rs"));
        let link = links.iter().find(|l| l.rel == "link.rs").expect("symlink captured");
        assert_eq!(link.target, "src/main.rs");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
