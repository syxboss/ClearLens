use crate::{AllowedRuleHit, AppState};
use clearlens_core::{
    clean_duplicates, clean_orphan_paths, execute_clean_with_elevation, load_all_rules,
    load_app_config, platform, read_audit_history, run_rule_scan, scan_apps_and_orphans,
    scan_duplicates, scan_space_lens, scan_virtual_disks as core_scan_vdisks,
    thin_local_snapshots as core_thin_snapshots, uninstall_app_paths,
    update_ignore_list as core_update_ignore, update_workspace_roots as core_update_workspaces,
    AppConfig, AuditRecord, CleanItemRequest, CleanReport, DeleteMode, DiskOverview,
    DuplicateCleanGroup, DuplicateReport, RiskLevel, RuleFile, ScanOptions, ScanProgressEvent,
    ScanReport, SpaceLensReport, TargetPlatform, UninstallerReport, VirtualDiskReport,
};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use tauri::{ipc::Channel, State};

#[tauri::command]
pub fn get_disk_overview() -> Result<DiskOverview, String> {
    let rules = load_all_rules()?;
    let count: usize = rules.iter().map(|f| f.rules.len()).sum();
    Ok(platform::get_disk_overview(count))
}

#[tauri::command]
pub async fn start_rule_scan(
    categories: Option<Vec<String>>,
    stale_days: u32,
    state: State<'_, AppState>,
    on_event: Channel<ScanProgressEvent>,
) -> Result<ScanReport, String> {
    let cancel = state.begin_scan();
    let cfg = load_app_config();

    let report = tauri::async_runtime::spawn_blocking(move || {
        let mut last_emit = Instant::now();
        let opts = ScanOptions {
            platform: TargetPlatform::current(),
            categories,
            stale_days,
            workspace_roots: cfg.workspace_roots,
            ignore_paths: cfg.ignore_paths,
        };
        run_rule_scan(&opts, &cancel, |ev| {
            let is_terminal = matches!(ev, ScanProgressEvent::Completed { .. });
            if is_terminal || last_emit.elapsed() >= Duration::from_millis(100) {
                let _ = on_event.send(ev);
                last_emit = Instant::now();
            }
        })
    })
    .await
    .map_err(|e| format!("scan worker panicked: {e}"))??;

    state.replace_rule_hits(report.hits.iter().map(|h| {
        (
            h.path.clone(),
            AllowedRuleHit {
                rule_id: h.rule_id.clone(),
                risk: h.risk,
                delete_mode: h.delete_mode,
                native_command: h.native_command.clone(),
            },
        )
    }));
    Ok(report)
}

#[tauri::command]
pub async fn run_clean(
    items: Vec<CleanItemRequest>,
    dry_run: bool,
    state: State<'_, AppState>,
) -> Result<CleanReport, String> {
    let mut sanitized = Vec::with_capacity(items.len());
    for item in items {
        if item.rule_id == "lens.cold_file" {
            if !state.is_cold_file_allowed(&item.path) {
                return Err(format!(
                    "IPC guard rejected unscanned cold file path: {}",
                    item.path.display()
                ));
            }
            sanitized.push(CleanItemRequest {
                rule_id: "lens.cold_file".to_string(),
                path: item.path,
                risk: RiskLevel::ReviewRequired,
                delete_mode: DeleteMode::Trash,
                native_command: None,
            });
        } else if let Some(saved) = state.get_allowed_rule_hit(&item.path) {
            if saved.rule_id != item.rule_id {
                return Err(format!(
                    "IPC guard rejected mismatched rule '{}' for path {}",
                    item.rule_id,
                    item.path.display()
                ));
            }
            sanitized.push(CleanItemRequest {
                rule_id: saved.rule_id,
                path: item.path,
                risk: saved.risk,
                delete_mode: saved.delete_mode,
                native_command: saved.native_command,
            });
        } else {
            return Err(format!(
                "IPC guard rejected unscanned target path: {}",
                item.path.display()
            ));
        }
    }
    tauri::async_runtime::spawn_blocking(move || execute_clean_with_elevation(&sanitized, dry_run))
        .await
        .map_err(|e| format!("clean worker panicked: {e}"))
}

#[tauri::command]
pub async fn start_space_lens(
    path: String,
    min_cold_mb: u64,
    cold_days: u32,
    state: State<'_, AppState>,
    on_event: Channel<ScanProgressEvent>,
) -> Result<SpaceLensReport, String> {
    let cancel = state.begin_scan();

    let report = tauri::async_runtime::spawn_blocking(move || {
        let mut last_emit = Instant::now();
        let target = clearlens_core::config::normalize_user_path(Path::new(&path));
        scan_space_lens(
            &target,
            min_cold_mb.saturating_mul(1_048_576),
            cold_days,
            &cancel,
            |ev| {
                let is_terminal = matches!(ev, ScanProgressEvent::Completed { .. });
                if is_terminal || last_emit.elapsed() >= Duration::from_millis(100) {
                    let _ = on_event.send(ev);
                    last_emit = Instant::now();
                }
            },
        )
    })
    .await
    .map_err(|e| format!("lens worker panicked: {e}"))??;

    state.allow_cold_files(report.cold_files.iter().map(|cf| cf.path.clone()));
    Ok(report)
}

#[tauri::command]
pub async fn start_duplicate_scan(
    paths: Vec<String>,
    min_size_kb: u64,
    state: State<'_, AppState>,
    on_event: Channel<ScanProgressEvent>,
) -> Result<DuplicateReport, String> {
    let cancel = state.begin_scan();

    let report = tauri::async_runtime::spawn_blocking(move || {
        let roots: Vec<PathBuf> = paths
            .into_iter()
            .map(|p| clearlens_core::config::normalize_user_path(Path::new(&p)))
            .collect();
        scan_duplicates(&roots, min_size_kb.saturating_mul(1024), &cancel, |ev| {
            let _ = on_event.send(ev);
        })
    })
    .await
    .map_err(|e| format!("duplicate scan panicked: {e}"))??;

    state.replace_duplicate_paths(
        report
            .groups
            .iter()
            .flat_map(|g| g.entries.iter().map(|e| e.path.clone())),
    );
    Ok(report)
}

#[tauri::command]
pub async fn clean_duplicate_groups(
    groups: Vec<DuplicateCleanGroup>,
    dry_run: bool,
    state: State<'_, AppState>,
) -> Result<CleanReport, String> {
    for grp in &groups {
        for p in grp.delete_paths.iter().chain(grp.all_paths.iter()) {
            if !state.is_duplicate_path_allowed(p) {
                return Err(format!(
                    "IPC guard rejected unscanned duplicate path: {}",
                    p.display()
                ));
            }
        }
    }
    tauri::async_runtime::spawn_blocking(move || clean_duplicates(&groups, dry_run))
        .await
        .map_err(|e| format!("duplicate clean panicked: {e}"))?
}

#[tauri::command]
pub async fn scan_uninstaller(
    min_orphan_days: u32,
    state: State<'_, AppState>,
) -> Result<UninstallerReport, String> {
    let cancel = state.begin_scan();

    let report = tauri::async_runtime::spawn_blocking(move || {
        scan_apps_and_orphans(TargetPlatform::current(), min_orphan_days, &cancel)
    })
    .await
    .map_err(|e| format!("uninstaller scan panicked: {e}"))??;

    let orphans: Vec<PathBuf> = report.orphans.iter().map(|o| o.path.clone()).collect();
    let mut apps = Vec::new();
    for app in &report.apps {
        apps.push(app.install_path.clone());
        for r in &app.residues {
            apps.push(r.path.clone());
        }
    }
    state.replace_uninstaller_paths(orphans, apps);
    Ok(report)
}

#[tauri::command]
pub async fn clean_orphans(
    paths: Vec<String>,
    dry_run: bool,
    state: State<'_, AppState>,
) -> Result<CleanReport, String> {
    let pbufs: Vec<PathBuf> = paths.into_iter().map(PathBuf::from).collect();
    for p in &pbufs {
        if !state.is_orphan_path_allowed(p) {
            return Err(format!(
                "IPC guard rejected unscanned orphan path: {}",
                p.display()
            ));
        }
    }
    tauri::async_runtime::spawn_blocking(move || clean_orphan_paths(&pbufs, dry_run))
        .await
        .map_err(|e| format!("orphan clean panicked: {e}"))
}

#[tauri::command]
pub async fn uninstall_app(
    app_name: String,
    paths: Vec<String>,
    dry_run: bool,
    state: State<'_, AppState>,
) -> Result<CleanReport, String> {
    let pbufs: Vec<PathBuf> = paths.into_iter().map(PathBuf::from).collect();
    for p in &pbufs {
        if !state.is_app_path_allowed(p) {
            return Err(format!(
                "IPC guard rejected unscanned app path: {}",
                p.display()
            ));
        }
    }
    tauri::async_runtime::spawn_blocking(move || uninstall_app_paths(&app_name, &pbufs, dry_run))
        .await
        .map_err(|e| format!("uninstall panicked: {e}"))
}

#[tauri::command]
pub fn cancel_scan(state: State<'_, AppState>) -> Result<(), String> {
    state.cancel_current();
    Ok(())
}

#[tauri::command]
pub fn get_builtin_rules() -> Result<Vec<RuleFile>, String> {
    load_all_rules()
}

#[tauri::command]
pub fn get_audit_history(limit: usize) -> Result<Vec<AuditRecord>, String> {
    Ok(read_audit_history(limit))
}

#[tauri::command]
pub fn get_app_config() -> Result<AppConfig, String> {
    Ok(load_app_config())
}

#[tauri::command]
pub fn update_ignore_list(path: String, remove: bool) -> Result<AppConfig, String> {
    core_update_ignore(PathBuf::from(path), remove).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn update_workspace_roots(path: String, remove: bool) -> Result<AppConfig, String> {
    core_update_workspaces(PathBuf::from(path), remove).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn thin_local_snapshots(gb: u64, dry_run: bool) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        core_thin_snapshots(gb.saturating_mul(1_073_741_824), dry_run)
    })
    .await
    .map_err(|e| format!("snapshot thinning panicked: {e}"))?
}

#[tauri::command]
pub async fn scan_virtual_disks() -> Result<VirtualDiskReport, String> {
    tauri::async_runtime::spawn_blocking(|| core_scan_vdisks(TargetPlatform::current()))
        .await
        .map_err(|e| format!("vdisk scan panicked: {e}"))
}

#[tauri::command]
pub fn reveal_in_folder(path: String) -> Result<(), String> {
    let target = clearlens_core::config::normalize_user_path(Path::new(&path));
    if !target.exists() {
        return Err(format!("path does not exist: {}", target.display()));
    }
    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg("-R")
            .arg(&target)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let win_path = target.to_string_lossy().replace('/', "\\").replace('"', "");
        Command::new("explorer")
            .raw_arg(format!("/select,\"{win_path}\""))
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = target;
    }
    Ok(())
}

#[tauri::command]
pub fn open_fda_settings() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg("x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
