use super::{is_icloud_stub_name, FilePhysicalMeta};
use crate::models::{DiskOverview, TargetPlatform, VolumeInfo};
use std::collections::HashSet;
use std::ffi::CString;
use std::os::unix::fs::MetadataExt as UnixMetadataExt;
use std::path::Path;
use std::time::UNIX_EPOCH;

pub fn inspect_path_meta_linux(path: &Path) -> std::io::Result<FilePhysicalMeta> {
    let meta = std::fs::symlink_metadata(path)?;
    let is_symlink = meta.file_type().is_symlink();
    let is_dir = !is_symlink && meta.is_dir();
    let is_cloud = is_icloud_stub_name(path);

    let logical = meta.len();
    let alloc_raw = meta.blocks().saturating_mul(512);
    let allocated_bytes = if is_symlink || is_cloud || is_dir {
        0
    } else if logical == 0 {
        0
    } else if alloc_raw == 0 && logical <= 4096 {
        logical
    } else {
        alloc_raw
    };

    let mtime_secs = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let atime_secs = meta
        .accessed()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(mtime_secs);

    Ok(FilePhysicalMeta {
        allocated_bytes,
        logical_bytes: logical,
        is_dir,
        is_symlink_or_reparse: is_symlink,
        is_cloud_placeholder: is_cloud,
        dev: meta.dev(),
        ino: meta.ino(),
        nlink: meta.nlink(),
        mtime_secs,
        atime_secs,
    })
}

fn statvfs_path(path: &str) -> (u64, u64) {
    unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        let Ok(cpath) = CString::new(path) else {
            return (0, 0);
        };
        if libc::statvfs(cpath.as_ptr(), &mut stat) == 0 {
            let frsize = if stat.f_frsize > 0 {
                stat.f_frsize as u64
            } else {
                stat.f_bsize as u64
            };
            let total = (stat.f_blocks as u64).saturating_mul(frsize);
            let avail = (stat.f_bavail as u64).saturating_mul(frsize);
            (total, avail)
        } else {
            (0, 0)
        }
    }
}

pub fn get_disk_overview_linux(rule_count: usize) -> DiskOverview {
    let (total_bytes, available_bytes) = statvfs_path("/");
    let mut volumes = Vec::new();
    let mut seen = HashSet::new();

    if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
        for line in mounts.lines() {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 3 {
                continue;
            }
            let mount = cols[1];
            let fstype = cols[2];
            let is_candidate = mount == "/"
                || mount.starts_with("/mnt/")
                || mount.starts_with("/media/")
                || mount == "/home";
            if !is_candidate
                || !matches!(
                    fstype,
                    "ext4" | "ext3" | "xfs" | "btrfs" | "overlay" | "zfs" | "apfs" | "virtiofs"
                )
            {
                continue;
            }
            if !seen.insert(mount.to_string()) {
                continue;
            }
            let (t, a) = statvfs_path(mount);
            if t > 0 {
                volumes.push(VolumeInfo {
                    mount_point: mount.to_string(),
                    label: if mount == "/" {
                        "Root (/)".to_string()
                    } else {
                        mount.to_string()
                    },
                    total_bytes: t,
                    available_bytes: a,
                    used_bytes: t.saturating_sub(a),
                    purgeable_bytes: 0,
                    is_system: mount == "/",
                });
            }
        }
    }

    if volumes.is_empty() && total_bytes > 0 {
        volumes.push(VolumeInfo {
            mount_point: "/".to_string(),
            label: "Root (/)".to_string(),
            total_bytes,
            available_bytes,
            used_bytes: total_bytes.saturating_sub(available_bytes),
            purgeable_bytes: 0,
            is_system: true,
        });
    }

    DiskOverview {
        platform: TargetPlatform::Linux,
        mount_point: "/".to_string(),
        total_bytes,
        available_bytes,
        used_bytes: total_bytes.saturating_sub(available_bytes),
        purgeable_bytes: 0,
        important_available_bytes: available_bytes,
        fda_granted: true,
        local_snapshots_count: 0,
        rule_count,
        volumes,
    }
}
