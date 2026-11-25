use super::{is_icloud_stub_name, FilePhysicalMeta};
use crate::models::{DiskOverview, TargetPlatform, VolumeInfo};
use std::ffi::{c_void, CString};
use std::os::macos::fs::MetadataExt as MacMetadataExt;
use std::os::unix::fs::MetadataExt as UnixMetadataExt;
use std::path::Path;
use std::process::Command;
use std::time::UNIX_EPOCH;

const SF_DATALESS: u32 = 0x4000_0000;

pub fn inspect_path_meta_macos(path: &Path) -> std::io::Result<FilePhysicalMeta> {
    let meta = std::fs::symlink_metadata(path)?;
    let is_symlink = meta.file_type().is_symlink();
    let is_dir = !is_symlink && meta.is_dir();
    let is_dataless = (meta.st_flags() & SF_DATALESS) != 0 || is_icloud_stub_name(path);

    let logical = meta.len();
    let alloc_raw = meta.blocks().saturating_mul(512);
    let allocated_bytes = if is_symlink || is_dataless || is_dir {
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
        is_cloud_placeholder: is_dataless,
        dev: meta.dev(),
        ino: meta.ino(),
        nlink: meta.nlink(),
        mtime_secs,
        atime_secs,
    })
}

pub fn get_disk_overview_macos(rule_count: usize) -> DiskOverview {
    let (total_bytes, available_bytes) = statfs_path("/");
    let important_available_bytes = query_important_available_capacity("/").unwrap_or(available_bytes);
    let purgeable_bytes = important_available_bytes.saturating_sub(available_bytes);
    let used_bytes = total_bytes.saturating_sub(available_bytes);
    let fda_granted = check_full_disk_access();
    let local_snapshots_count = count_local_tm_snapshots();
    let volumes = enumerate_macos_volumes(total_bytes, available_bytes, purgeable_bytes);

    DiskOverview {
        platform: TargetPlatform::MacOs,
        mount_point: "/".to_string(),
        total_bytes,
        available_bytes,
        used_bytes,
        purgeable_bytes,
        important_available_bytes,
        fda_granted,
        local_snapshots_count,
        rule_count,
        volumes,
    }
}

fn enumerate_macos_volumes(root_total: u64, root_avail: u64, root_purge: u64) -> Vec<VolumeInfo> {
    let mut vols = vec![VolumeInfo {
        mount_point: "/".to_string(),
        label: "Macintosh HD".to_string(),
        total_bytes: root_total,
        available_bytes: root_avail,
        used_bytes: root_total.saturating_sub(root_avail),
        purgeable_bytes: root_purge,
        is_system: true,
    }];

    if let Ok(entries) = std::fs::read_dir("/Volumes") {
        for entry in entries.flatten() {
            let p = entry.path();
            if std::fs::symlink_metadata(&p)
                .map(|m| m.file_type().is_symlink() || !m.is_dir())
                .unwrap_or(true)
            {
                continue;
            }
            let mount_str = p.to_string_lossy().to_string();
            let (total, avail) = statfs_path(&mount_str);
            if total == 0 {
                continue;
            }
            let important = query_important_available_capacity(&mount_str).unwrap_or(avail);
            let label = entry.file_name().to_string_lossy().to_string();
            vols.push(VolumeInfo {
                mount_point: mount_str,
                label,
                total_bytes: total,
                available_bytes: avail,
                used_bytes: total.saturating_sub(avail),
                purgeable_bytes: important.saturating_sub(avail),
                is_system: false,
            });
        }
    }
    vols
}

pub fn thin_local_snapshots_macos(bytes_to_free: u64, dry_run: bool) -> Result<String, String> {
    let target = bytes_to_free.max(1_073_741_824);
    if dry_run {
        return Ok(format!("[dry-run] tmutil thinlocalsnapshots / {target} 4"));
    }
    let out = Command::new("tmutil")
        .args(["thinlocalsnapshots", "/", &target.to_string(), "4"])
        .output()
        .map_err(|e| format!("failed to execute tmutil: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn statfs_path(path: &str) -> (u64, u64) {
    unsafe {
        let mut stat: libc::statfs = std::mem::zeroed();
        let Ok(cpath) = CString::new(path) else {
            return (0, 0);
        };
        if libc::statfs(cpath.as_ptr(), &mut stat) == 0 {
            let bsize = stat.f_bsize as u64;
            let total = (stat.f_blocks as u64).saturating_mul(bsize);
            let avail = (stat.f_bavail as u64).saturating_mul(bsize);
            (total, avail)
        } else {
            (0, 0)
        }
    }
}

fn check_full_disk_access() -> bool {
    if let Some(home) = super::resolve_home_dir() {
        for probe in [
            home.join("Library/Safari"),
            home.join("Library/Messages"),
            home.join("Library/Application Support/com.apple.TCC"),
        ] {
            match std::fs::read_dir(&probe) {
                Ok(_) => return true,
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return false,
                Err(_) => continue,
            }
        }
    }
    true
}

fn count_local_tm_snapshots() -> usize {
    Command::new("tmutil")
        .arg("listlocalsnapshots")
        .arg("/")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| l.contains("com.apple.TimeMachine"))
                .count()
        })
        .unwrap_or(0)
}

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFURLCreateFromFileSystemRepresentation(
        allocator: *const c_void,
        buffer: *const u8,
        buf_len: isize,
        is_directory: u8,
    ) -> *const c_void;
    fn CFStringCreateWithCString(
        alloc: *const c_void,
        c_str: *const i8,
        encoding: u32,
    ) -> *const c_void;
    fn CFURLCopyResourcePropertyForKey(
        url: *const c_void,
        key: *const c_void,
        property_value_type_ref_ptr: *mut *const c_void,
        error: *mut *const c_void,
    ) -> u8;
    fn CFNumberGetValue(number: *const c_void, the_type: isize, value_ptr: *mut c_void) -> u8;
    fn CFRelease(cf: *const c_void);
}

fn query_important_available_capacity(path: &str) -> Option<u64> {
    const UTF8: u32 = 0x0800_0100;
    const SINT64_TYPE: isize = 4;

    unsafe {
        let url = CFURLCreateFromFileSystemRepresentation(
            std::ptr::null(),
            path.as_ptr(),
            path.len() as isize,
            1,
        );
        if url.is_null() {
            return None;
        }
        let key_c = CString::new("NSURLVolumeAvailableCapacityForImportantUsageKey").ok()?;
        let key = CFStringCreateWithCString(std::ptr::null(), key_c.as_ptr(), UTF8);
        if key.is_null() {
            CFRelease(url);
            return None;
        }
        let mut value_ref: *const c_void = std::ptr::null();
        let mut err_ref: *const c_void = std::ptr::null();
        let ok = CFURLCopyResourcePropertyForKey(url, key, &mut value_ref, &mut err_ref);
        let mut result: Option<u64> = None;
        if ok != 0 && !value_ref.is_null() {
            let mut val: i64 = 0;
            if CFNumberGetValue(value_ref, SINT64_TYPE, &mut val as *mut i64 as *mut c_void) != 0
                && val >= 0
            {
                result = Some(val as u64);
            }
            CFRelease(value_ref);
        }
        if !err_ref.is_null() {
            CFRelease(err_ref);
        }
        CFRelease(key);
        CFRelease(url);
        result
    }
}
