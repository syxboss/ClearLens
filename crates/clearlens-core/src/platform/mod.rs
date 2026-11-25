pub mod elevation;

use crate::models::{DiskOverview, TargetPlatform};
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;
#[cfg(all(unix, not(target_os = "macos")))]
mod linux;

#[derive(Debug, Clone)]
pub struct FilePhysicalMeta {
    pub allocated_bytes: u64,
    pub logical_bytes: u64,
    pub is_dir: bool,
    pub is_symlink_or_reparse: bool,
    pub is_cloud_placeholder: bool,
    pub dev: u64,
    pub ino: u64,
    pub nlink: u64,
    pub mtime_secs: i64,
    pub atime_secs: i64,
}

pub fn inspect_path_meta(path: &Path) -> std::io::Result<FilePhysicalMeta> {
    #[cfg(target_os = "macos")]
    {
        macos::inspect_path_meta_macos(path)
    }
    #[cfg(windows)]
    {
        windows::inspect_path_meta_windows(path)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        linux::inspect_path_meta_linux(path)
    }
}

pub fn get_disk_overview(rule_count: usize) -> DiskOverview {
    #[cfg(target_os = "macos")]
    {
        macos::get_disk_overview_macos(rule_count)
    }
    #[cfg(windows)]
    {
        windows::get_disk_overview_windows(rule_count)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        linux::get_disk_overview_linux(rule_count)
    }
}

pub fn thin_local_snapshots(bytes_to_free: u64, dry_run: bool) -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        macos::thin_local_snapshots_macos(bytes_to_free, dry_run)
    }
    #[cfg(not(target_os = "macos"))]
    {
        if dry_run {
            Ok(format!(
                "[dry-run] APFS snapshot thinning ({bytes_to_free} bytes) is only applicable on macOS"
            ))
        } else {
            Err("APFS local snapshot thinning is only available on macOS".to_string())
        }
    }
}

pub fn move_to_os_trash(path: &Path) -> Result<(), String> {
    if let Some(custom_dir) = std::env::var_os("CLEARLENS_TRASH_DIR").filter(|v| !v.is_empty()) {
        return move_to_trash_dir_atomic(path, Path::new(&custom_dir))
            .map_err(|e| format!("custom trash failed: {e}"));
    }
    #[cfg(windows)]
    {
        trash::delete(path).map_err(|e| format!("OS trash failed: {e}"))
    }
    #[cfg(unix)]
    {
        match trash::delete(path) {
            Ok(()) => Ok(()),
            Err(primary_err) => unix_trash_fallback(path)
                .map_err(|fb_err| format!("trash failed ({primary_err}); fallback failed ({fb_err})")),
        }
    }
}

#[cfg(unix)]
fn unix_trash_fallback(path: &Path) -> std::io::Result<()> {
    let base = if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
        PathBuf::from(xdg).join("Trash")
    } else if cfg!(target_os = "macos") {
        resolve_home_dir()
            .map(|h| h.join(".Trash"))
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no HOME for Trash"))?
    } else {
        resolve_home_dir()
            .map(|h| h.join(".local/share/Trash"))
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no HOME for Trash"))?
    };
    move_to_trash_dir_atomic(path, &base)
}

fn move_to_trash_dir_atomic(path: &Path, base: &Path) -> std::io::Result<()> {
    use std::io::Write;

    let trash_files = base.join("files");
    let trash_info = base.join("info");
    std::fs::create_dir_all(&trash_files)?;
    std::fs::create_dir_all(&trash_info)?;

    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "item".to_string());
    let stamp = chrono::Utc::now().timestamp_millis();
    let encoded_orig = percent_encode_trash_path(&path.to_string_lossy());
    let info_content = format!(
        "[Trash Info]\nPath={}\nDeletionDate={}\n",
        encoded_orig,
        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S")
    );

    // Atomically reserve a unique `.trashinfo` + `files/` slot so rapid same-millisecond
    // deletions of identically-named files (e.g. 3+ duplicate copies) NEVER overwrite each other.
    let mut chosen_dest: Option<(PathBuf, PathBuf)> = None;
    for attempt in 0..10_000u32 {
        let candidate = if attempt == 0 {
            name.clone()
        } else {
            format!("{name}.{stamp}.{attempt}")
        };
        let dest = trash_files.join(&candidate);
        if std::fs::symlink_metadata(&dest).is_ok() {
            continue;
        }
        let info_path = trash_info.join(format!("{candidate}.trashinfo"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&info_path)
        {
            Ok(mut info_file) => {
                info_file.write_all(info_content.as_bytes())?;
                chosen_dest = Some((dest, info_path));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }

    let (dest, info_path) = chosen_dest.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "unable to allocate unique Trash entry",
        )
    })?;

    if std::fs::rename(path, &dest).is_err() {
        if let Err(copy_err) = copy_and_remove_fallback(path, &dest) {
            let _ = std::fs::remove_file(&info_path);
            return Err(copy_err);
        }
    }
    Ok(())
}

fn percent_encode_trash_path(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn copy_and_remove_fallback(src: &Path, dst: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(src)?;
    if meta.file_type().is_symlink() {
        #[cfg(unix)]
        {
            let link_target = std::fs::read_link(src)?;
            std::os::unix::fs::symlink(&link_target, dst)?;
            std::fs::remove_file(src)?;
        }
        #[cfg(windows)]
        {
            if meta.is_dir() {
                std::fs::remove_dir(src)?;
            } else {
                std::fs::remove_file(src)?;
            }
        }
    } else if meta.is_dir() {
        std::fs::create_dir_all(dst)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            copy_and_remove_fallback(&entry.path(), &dst.join(entry.file_name()))?;
        }
        std::fs::remove_dir(src)?;
    } else {
        std::fs::copy(src, dst)?;
        std::fs::remove_file(src)?;
    }
    Ok(())
}

pub fn resolve_home_dir() -> Option<PathBuf> {
    if let Some(h) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(h));
    }
    if let Some(h) = std::env::var_os("USERPROFILE").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(h));
    }
    dirs::home_dir()
}

pub fn is_icloud_stub_name(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|name| name.starts_with('.') && name.ends_with(".icloud"))
        .unwrap_or(false)
}

pub fn current_platform() -> TargetPlatform {
    TargetPlatform::current()
}
