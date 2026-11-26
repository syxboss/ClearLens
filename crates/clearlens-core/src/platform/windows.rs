use super::FilePhysicalMeta;
use crate::models::{DiskOverview, TargetPlatform, VolumeInfo};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt as WinMetadataExt;
use std::path::Path;
use std::time::UNIX_EPOCH;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, INVALID_HANDLE_VALUE, NO_ERROR,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetCompressedFileSizeW, GetDiskFreeSpaceExW, GetDriveTypeW,
    GetFileInformationByHandle, GetLogicalDrives, BY_HANDLE_FILE_INFORMATION,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, INVALID_FILE_SIZE, OPEN_EXISTING,
};

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
const DRIVE_REMOVABLE: u32 = 2;
const DRIVE_FIXED: u32 = 3;

pub fn inspect_path_meta_windows(path: &Path) -> std::io::Result<FilePhysicalMeta> {
    let meta = std::fs::symlink_metadata(path)?;
    let attrs = meta.file_attributes();
    let is_reparse = meta.file_type().is_symlink() || (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
    let is_cloud = (attrs
        & (FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS))
        != 0
        || super::is_icloud_stub_name(path);
    let is_dir = !is_reparse && meta.is_dir();

    let logical = meta.file_size();
    let allocated_bytes = if is_reparse || is_cloud || is_dir {
        0
    } else {
        query_compressed_size(path).unwrap_or(logical)
    };

    // Metadata-only file identity lookup (dwDesiredAccess = 0 never triggers cloud recall)
    let (dev, ino, nlink) = if !is_reparse && !is_cloud && !is_dir {
        query_ntfs_file_id(path).unwrap_or((0, 0, 1))
    } else {
        (0, 0, 1)
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
        is_symlink_or_reparse: is_reparse,
        is_cloud_placeholder: is_cloud,
        dev,
        ino,
        nlink,
        mtime_secs,
        atime_secs,
    })
}

fn query_ntfs_file_id(path: &Path) -> Option<(u64, u64, u64)> {
    let wide: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let handle = CreateFileW(
            wide.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut info: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
        let ok = GetFileInformationByHandle(handle, &mut info);
        CloseHandle(handle);
        if ok == 0 {
            return None;
        }
        let dev = info.dwVolumeSerialNumber as u64;
        let ino = ((info.nFileIndexHigh as u64) << 32) | (info.nFileIndexLow as u64);
        let nlink = info.nNumberOfLinks as u64;
        Some((dev, ino, nlink))
    }
}

fn query_compressed_size(path: &Path) -> Option<u64> {
    let wide: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut high: u32 = 0;
    unsafe {
        let low = GetCompressedFileSizeW(wide.as_ptr(), &mut high);
        if low == INVALID_FILE_SIZE && GetLastError() != NO_ERROR {
            return None;
        }
        Some(((high as u64) << 32) | (low as u64))
    }
}

fn query_volume_space(mount: &str) -> Option<(u64, u64)> {
    let wide: Vec<u16> = OsStr::new(mount)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut free_to_caller: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut total_free: u64 = 0;
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free_to_caller,
            &mut total_bytes,
            &mut total_free,
        )
    };
    if ok == 0 || total_bytes == 0 {
        None
    } else {
        Some((total_bytes, free_to_caller))
    }
}

pub fn get_disk_overview_windows(rule_count: usize) -> DiskOverview {
    let sys_drive = std::env::var("SystemDrive")
        .unwrap_or_else(|_| "C:".to_string())
        .to_ascii_uppercase();
    let sys_mount = format!("{sys_drive}\\");
    let (total_bytes, available_bytes) = query_volume_space(&sys_mount).unwrap_or((0, 0));

    let mut volumes = Vec::new();
    let mask = unsafe { GetLogicalDrives() };
    for idx in 0..26u32 {
        if (mask & (1 << idx)) == 0 {
            continue;
        }
        let letter = (b'A' + idx as u8) as char;
        let mount = format!("{letter}:\\");
        let wide: Vec<u16> = OsStr::new(&mount)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let dtype = unsafe { GetDriveTypeW(wide.as_ptr()) };
        if dtype != DRIVE_FIXED && dtype != DRIVE_REMOVABLE {
            continue;
        }
        if let Some((total, avail)) = query_volume_space(&mount) {
            volumes.push(VolumeInfo {
                mount_point: mount.clone(),
                label: format!("Local Disk ({letter}:)"),
                total_bytes: total,
                available_bytes: avail,
                used_bytes: total.saturating_sub(avail),
                purgeable_bytes: 0,
                is_system: mount.eq_ignore_ascii_case(&sys_mount),
            });
        }
    }

    DiskOverview {
        platform: TargetPlatform::Windows,
        mount_point: sys_mount,
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
