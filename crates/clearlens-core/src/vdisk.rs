use crate::models::{TargetPlatform, VirtualDiskEntry, VirtualDiskKind, VirtualDiskReport};
use crate::platform::{inspect_path_meta, resolve_home_dir};
use crate::safety::ProcessMonitor;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Inspects WSL2, Docker Desktop, OrbStack, and Lima/Colima virtual disk images
/// without deleting or modifying them, reporting true physical SSD allocation vs.
/// logical ceiling and generating safe OS-native compaction commands/scripts.
pub fn scan_virtual_disks(platform: TargetPlatform) -> VirtualDiskReport {
    let start = Instant::now();
    let proc_mon = ProcessMonitor::snapshot();
    let mut disks = Vec::new();

    match platform {
        TargetPlatform::Windows => collect_windows_vdisks(&proc_mon, &mut disks),
        TargetPlatform::MacOs => collect_macos_vdisks(&proc_mon, &mut disks),
        TargetPlatform::Linux => collect_linux_vdisks(&proc_mon, &mut disks),
    }

    disks.sort_by(|a, b| b.allocated_bytes.cmp(&a.allocated_bytes));
    let total_allocated_bytes = disks
        .iter()
        .fold(0u64, |acc, d| acc.saturating_add(d.allocated_bytes));
    let total_logical_bytes = disks
        .iter()
        .fold(0u64, |acc, d| acc.saturating_add(d.logical_bytes));

    VirtualDiskReport {
        platform,
        duration_ms: start.elapsed().as_millis() as u64,
        total_allocated_bytes,
        total_logical_bytes,
        disks,
    }
}

fn collect_windows_vdisks(proc_mon: &ProcessMonitor, out: &mut Vec<VirtualDiskEntry>) {
    let Some(home) = resolve_home_dir() else {
        return;
    };
    let local_appdata = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| home.join("AppData/Local"));

    let docker_running = proc_mon
        .find_running(&["Docker Desktop.exe".into(), "com.docker.backend.exe".into()])
        .is_some();
    let wsl_running = proc_mon
        .find_running(&["vmmem".into(), "vmmemWSL".into(), "wslservice.exe".into()])
        .is_some();

    // 1. Docker Desktop WSL2 virtual disks
    let docker_candidates = [
        local_appdata.join("Docker/wsl/disk/docker_data.vhdx"),
        local_appdata.join("Docker/wsl/data/ext4.vhdx"),
        local_appdata.join("Docker/wsl/main/ext4.vhdx"),
    ];
    for p in docker_candidates {
        if let Some(entry) = build_windows_vhdx_entry(
            p,
            VirtualDiskKind::DockerDesktopVhdx,
            "Docker Desktop (WSL2 VHDX)".to_string(),
            docker_running || wsl_running,
        ) {
            out.push(entry);
        }
    }

    // 2. Installed WSL2 Linux distros under %LOCALAPPDATA%/Packages/*/LocalState/ext4.vhdx
    let packages_dir = local_appdata.join("Packages");
    if let Ok(entries) = fs::read_dir(&packages_dir) {
        for entry in entries.flatten() {
            let pkg_name = entry.file_name().to_string_lossy().to_string();
            let vhdx = entry.path().join("LocalState").join("ext4.vhdx");
            if vhdx.is_file() {
                let distro_label = pkg_name
                    .split('_')
                    .next()
                    .unwrap_or(&pkg_name)
                    .to_string();
                if let Some(item) = build_windows_vhdx_entry(
                    vhdx,
                    VirtualDiskKind::Wsl2Vhdx,
                    format!("WSL2 Distro: {distro_label}"),
                    wsl_running,
                ) {
                    out.push(item);
                }
            }
        }
    }
}

fn build_windows_vhdx_entry(
    path: PathBuf,
    kind: VirtualDiskKind,
    name: String,
    is_in_use: bool,
) -> Option<VirtualDiskEntry> {
    let meta = inspect_path_meta(&path).ok()?;
    if meta.is_dir || meta.is_symlink_or_reparse || meta.is_cloud_placeholder {
        return None;
    }
    if meta.logical_bytes == 0 && meta.allocated_bytes == 0 {
        return None;
    }

    let path_str = path.display().to_string();
    let ps_escaped = path_str.replace('\'', "''");
    let compact_command = format!(
        "wsl --shutdown; Optimize-VHD -Path '{ps_escaped}' -Mode Full"
    );
    let compact_script = build_windows_vhdx_compact_script(&path_str);

    Some(VirtualDiskEntry {
        id: format!("vdisk::{}", path.display()),
        kind,
        name,
        path,
        allocated_bytes: meta.allocated_bytes,
        logical_bytes: meta.logical_bytes,
        sparse_savings_bytes: meta.logical_bytes.saturating_sub(meta.allocated_bytes),
        is_in_use,
        requires_elevation: true,
        compact_command,
        compact_script,
        safety_note: "Always run `wsl --shutdown` and quit Docker Desktop first. Never delete .vhdx files directly; compact them in-place to reclaim internal free blocks safely.".to_string(),
        safety_note_zh: "压缩前必须先执行 `wsl --shutdown` 并完全退出 Docker Desktop。严禁直接删除 .vhdx 文件，仅通过安全原地压缩回收内部空洞空间。".to_string(),
    })
}

fn build_windows_vhdx_compact_script(vhdx_path: &str) -> String {
    // PowerShell single-quoted string literal prevents `$` or backtick expansion in file paths
    let ps_single_escaped = vhdx_path.replace('\'', "''");
    let dp_double_stripped = vhdx_path.replace('"', "");
    format!(
        r#"# Run in an Administrator PowerShell window
wsl --shutdown
$vhdx = '{ps_single_escaped}'
if (Get-Command Optimize-VHD -ErrorAction SilentlyContinue) {{
    Optimize-VHD -Path $vhdx -Mode Full
}} else {{
    # Works on Windows 10/11 Home & Pro without Hyper-V PowerShell module
    @(
        'select vdisk file="{dp_double_stripped}"'
        'attach vdisk readonly'
        'compact vdisk'
        'detach vdisk'
    ) | diskpart
}}"#
    )
}

fn collect_macos_vdisks(proc_mon: &ProcessMonitor, out: &mut Vec<VirtualDiskEntry>) {
    let Some(home) = resolve_home_dir() else {
        return;
    };

    let docker_running = proc_mon
        .find_running(&["Docker Desktop".into(), "com.docker.backend".into()])
        .is_some();
    let orb_running = proc_mon.find_running(&["OrbStack".into()]).is_some();
    let lima_running = proc_mon
        .find_running(&["limactl".into(), "qemu-system".into()])
        .is_some();

    // 1. Docker Desktop for Mac (`Docker.raw`)
    let docker_raw = home.join("Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw");
    if let Some(entry) = build_unix_vdisk_entry(
        docker_raw,
        VirtualDiskKind::DockerDesktopRawMac,
        "Docker Desktop (Docker.raw)".to_string(),
        docker_running,
        "docker builder prune -af && docker image prune -f".to_string(),
        "# 1. Reclaim unused layers & build cache inside Docker VM\ndocker builder prune -af\ndocker image prune -f\n# 2. If Docker.raw stays bloated on APFS, restart Docker Desktop or use Settings -> Resources -> Disk image size.".to_string(),
        "APFS stores Docker.raw as a sparse file; physical SSD usage is often much smaller than Finder's logical size. Prune via Docker CLI instead of deleting Docker.raw.".to_string(),
        "macOS APFS 以稀疏文件存储 Docker.raw，真实 SSD 占用通常远小于访达显示的逻辑上限；请通过 Docker CLI 回收内部空间，切勿直接删除该镜像。".to_string(),
    ) {
        out.push(entry);
    }

    // 2. OrbStack data disk (`~/Library/Group Containers/*.dev.orbstack/data/data.img`)
    let group_containers = home.join("Library/Group Containers");
    if let Ok(entries) = fs::read_dir(&group_containers) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".dev.orbstack") {
                let img = entry.path().join("data/data.img");
                if let Some(item) = build_unix_vdisk_entry(
                    img,
                    VirtualDiskKind::OrbStackImage,
                    "OrbStack VM Disk (data.img)".to_string(),
                    orb_running,
                    "docker builder prune -af && orbctl restart".to_string(),
                    "# Reclaim unused Docker build cache inside OrbStack\ndocker builder prune -af\ndocker image prune -f".to_string(),
                    "OrbStack auto-shrinks sparse images dynamically; prune unused Docker images & build cache to free blocks.".to_string(),
                    "OrbStack 会自动动态收缩稀疏镜像；执行镜像与构建缓存清理后即可自动释放宿主机空间。".to_string(),
                ) {
                    out.push(item);
                }
            }
        }
    }

    // 3. Lima / Colima VM diffdisks
    for base in [home.join(".lima"), home.join(".colima/_lima")] {
        collect_lima_diffdisks(&base, lima_running, out);
    }
}

fn collect_linux_vdisks(proc_mon: &ProcessMonitor, out: &mut Vec<VirtualDiskEntry>) {
    let Some(home) = resolve_home_dir() else {
        return;
    };
    let lima_running = proc_mon.find_running(&["limactl".into()]).is_some();
    for base in [home.join(".lima"), home.join(".colima/_lima")] {
        collect_lima_diffdisks(&base, lima_running, out);
    }
}

fn collect_lima_diffdisks(base: &Path, is_running: bool, out: &mut Vec<VirtualDiskEntry>) {
    let Ok(entries) = fs::read_dir(base) else {
        return;
    };
    for entry in entries.flatten() {
        let inst_name = entry.file_name().to_string_lossy().to_string();
        let diffdisk = entry.path().join("diffdisk");
        if diffdisk.is_file() {
            let cmd = format!("limactl shell {inst_name} sudo fstrim -av");
            let script = format!(
                "# Trim free blocks inside Lima/Colima VM '{inst_name}' so sparse disk compacts\nlimactl shell {inst_name} sudo fstrim -av"
            );
            if let Some(item) = build_unix_vdisk_entry(
                diffdisk,
                VirtualDiskKind::LimaColimaDisk,
                format!("Lima / Colima VM: {inst_name}"),
                is_running,
                cmd,
                script,
                "Run fstrim inside the VM to punch holes back to the host sparse filesystem safely.".to_string(),
                "在虚拟机内部执行 `fstrim` 通知宿主机回收稀疏空洞，安全且无损数据。".to_string(),
            ) {
                out.push(item);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn build_unix_vdisk_entry(
    path: PathBuf,
    kind: VirtualDiskKind,
    name: String,
    is_in_use: bool,
    compact_command: String,
    compact_script: String,
    safety_note: String,
    safety_note_zh: String,
) -> Option<VirtualDiskEntry> {
    let meta = inspect_path_meta(&path).ok()?;
    if meta.is_dir || meta.is_symlink_or_reparse || meta.is_cloud_placeholder {
        return None;
    }
    if meta.logical_bytes == 0 && meta.allocated_bytes == 0 {
        return None;
    }

    Some(VirtualDiskEntry {
        id: format!("vdisk::{}", path.display()),
        kind,
        name,
        path,
        allocated_bytes: meta.allocated_bytes,
        logical_bytes: meta.logical_bytes,
        sparse_savings_bytes: meta.logical_bytes.saturating_sub(meta.allocated_bytes),
        is_in_use,
        requires_elevation: false,
        compact_command,
        compact_script,
        safety_note,
        safety_note_zh,
    })
}
