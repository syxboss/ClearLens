use crate::cleaner::execute_clean;
use crate::config::{dir_contains_ignored, is_path_ignored, load_app_config, path_starts_with_for_policy, paths_equal_for_policy};
use crate::models::{
    AppResidueItem, CleanItemOutcome, CleanItemRequest, CleanReport, DeleteMode, InstalledAppEntry,
    OrphanResidue, RiskLevel, TargetPlatform, UninstallerReport,
};
use crate::platform::{inspect_path_meta, resolve_home_dir};
use crate::rules::smart_scanners::measure_dir_physical;
use crate::safety::{HardlinkDeduplicator, ProtectedBlocklist};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Protected vendor/system prefixes that are NEVER flagged as orphan app residues.
const SYSTEM_ORPHAN_ALLOWLIST: &[&str] = &[
    "com.apple.",
    "apple",
    "microsoft",
    "windows",
    "google",
    "mozilla",
    "clearlens",
    ".clearlens",
    "cloudkit",
    "clouddocs",
    "crashreporter",
    "crashdumps",
    "dock",
    "finder",
    "safari",
    "spotlight",
    "keychains",
    "caches",
    "logs",
    "preferences",
    "temporaryitems",
    "temp",
    "pip",
    "uv",
    "npm",
    "pnpm",
    "yarn",
    "bun",
    "cargo",
    "rustup",
    "huggingface",
    "ollama",
    "docker",
    "d3dscache",
    "nvidia",
    "amd",
    "mesa_shader_cache",
    "fontconfig",
    "thumbnails",
    "trash",
];

pub fn scan_apps_and_orphans(
    platform: TargetPlatform,
    min_orphan_days: u32,
    cancel: &AtomicBool,
) -> Result<UninstallerReport, String> {
    let start = Instant::now();
    let dedup = HardlinkDeduplicator::default();
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let (apps, orphans) = match platform {
        TargetPlatform::MacOs => scan_macos_apps_and_orphans(&dedup, min_orphan_days, now_secs, cancel),
        TargetPlatform::Windows => scan_windows_apps_and_orphans(&dedup, min_orphan_days, now_secs, cancel),
        TargetPlatform::Linux => scan_linux_apps_and_orphans(&dedup, min_orphan_days, now_secs, cancel),
    };

    if cancel.load(Ordering::Relaxed) {
        return Err("scan cancelled".to_string());
    }

    let total_orphan_bytes = orphans
        .iter()
        .fold(0u64, |acc, o| acc.saturating_add(o.allocated_bytes));

    Ok(UninstallerReport {
        platform,
        duration_ms: start.elapsed().as_millis() as u64,
        apps,
        orphans,
        total_orphan_bytes,
    })
}

pub fn clean_orphan_paths(paths: &[PathBuf], dry_run: bool) -> CleanReport {
    let allowed_roots = allowed_residue_roots();
    execute_scoped_uninstaller_clean(
        paths,
        dry_run,
        &allowed_roots,
        |_| "uninstaller.orphan_residue".to_string(),
        "orphan path outside permitted application residue directories",
    )
}

pub fn uninstall_app_paths(app_name: &str, paths: &[PathBuf], dry_run: bool) -> CleanReport {
    if is_clearlens_self_app(app_name, None, Path::new("")) {
        let outcomes: Vec<CleanItemOutcome> = paths
            .iter()
            .map(|p| CleanItemOutcome {
                rule_id: "uninstaller.app.clearlens".to_string(),
                path: p.clone(),
                requested_mode: DeleteMode::Trash,
                actual_mode: DeleteMode::Trash,
                freed_bytes: 0,
                success: false,
                error: Some("refusing self-uninstall of ClearLens".to_string()),
            })
            .collect();
        return CleanReport {
            dry_run,
            duration_ms: 0,
            total_freed_bytes: 0,
            succeeded_count: 0,
            failed_count: outcomes.len(),
            outcomes,
        };
    }

    let slug = app_name
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>();
    let mut allowed_roots = allowed_residue_roots();
    allowed_roots.extend(allowed_app_install_roots());

    execute_scoped_uninstaller_clean(
        paths,
        dry_run,
        &allowed_roots,
        move |_| format!("uninstaller.app.{slug}"),
        "path outside permitted application install/residue directories",
    )
}

fn execute_scoped_uninstaller_clean<F>(
    paths: &[PathBuf],
    dry_run: bool,
    allowed_roots: &[PathBuf],
    rule_id_fn: F,
    scope_err: &str,
) -> CleanReport
where
    F: Fn(&Path) -> String,
{
    let mut valid_items = Vec::new();
    let mut rejected = Vec::new();
    for p in paths {
        let rid = rule_id_fn(p);
        if is_clearlens_self_app("", None, p) {
            rejected.push(CleanItemOutcome {
                rule_id: rid,
                path: p.clone(),
                requested_mode: DeleteMode::Trash,
                actual_mode: DeleteMode::Trash,
                freed_bytes: 0,
                success: false,
                error: Some("refusing to remove ClearLens binary or bundle".to_string()),
            });
            continue;
        }
        if !is_strict_child_of_any(p, allowed_roots) {
            rejected.push(CleanItemOutcome {
                rule_id: rid,
                path: p.clone(),
                requested_mode: DeleteMode::Trash,
                actual_mode: DeleteMode::Trash,
                freed_bytes: 0,
                success: false,
                error: Some(format!("{scope_err}: {}", p.display())),
            });
            continue;
        }
        valid_items.push(CleanItemRequest {
            rule_id: rid,
            path: p.clone(),
            risk: RiskLevel::ReviewRequired,
            delete_mode: DeleteMode::Trash,
            native_command: None,
        });
    }

    let mut report = if valid_items.is_empty() {
        CleanReport {
            dry_run,
            duration_ms: 0,
            total_freed_bytes: 0,
            succeeded_count: 0,
            failed_count: 0,
            outcomes: Vec::new(),
        }
    } else {
        execute_clean(&valid_items, dry_run)
    };
    report.outcomes.extend(rejected);
    report.succeeded_count = report.outcomes.iter().filter(|o| o.success).count();
    report.failed_count = report.outcomes.iter().filter(|o| !o.success).count();
    report.total_freed_bytes = report
        .outcomes
        .iter()
        .filter(|o| o.success)
        .fold(0u64, |acc, o| acc.saturating_add(o.freed_bytes));
    report
}

fn allowed_residue_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(home) = resolve_home_dir() {
        let lib = home.join("Library");
        for sub in [
            "Application Support",
            "Caches",
            "Containers",
            "Saved Application State",
            "Preferences",
            "Logs",
        ] {
            roots.push(lib.join(sub));
        }
        roots.push(home.join("AppData/Local"));
        roots.push(home.join("AppData/Roaming"));
        roots.push(home.join(".cache"));
        roots.push(home.join(".config"));
    }
    if let Some(la) = std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()) {
        roots.push(PathBuf::from(la));
    }
    if let Some(ra) = std::env::var_os("APPDATA").filter(|v| !v.is_empty()) {
        roots.push(PathBuf::from(ra));
    }
    roots
}

fn allowed_app_install_roots() -> Vec<PathBuf> {
    let mut roots = vec![PathBuf::from("/Applications")];
    if let Some(ov) = std::env::var_os("CLEARLENS_APPS_DIR").filter(|v| !v.is_empty()) {
        roots.push(PathBuf::from(ov));
    }
    if let Some(home) = resolve_home_dir() {
        roots.push(home.join("Applications"));
        roots.push(home.join("AppData/Local/Programs"));
        roots.push(home.join(".local/share/applications"));
    }
    if let Some(la) = std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()) {
        roots.push(PathBuf::from(la).join("Programs"));
    }
    roots
}

fn is_strict_child_of_any(path: &Path, roots: &[PathBuf]) -> bool {
    roots
        .iter()
        .any(|r| path_starts_with_for_policy(path, r) && !paths_equal_for_policy(path, r))
}

fn is_clearlens_self_app(name: &str, bundle_id: Option<&str>, path: &Path) -> bool {
    if name.to_ascii_lowercase().contains("clearlens") {
        return true;
    }
    if bundle_id
        .map(|b| b.to_ascii_lowercase().contains("clearlens"))
        .unwrap_or(false)
    {
        return true;
    }
    let lower_path = path.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
    if lower_path.contains("dev.clearlens.app") || lower_path.contains("clearlens.app") {
        return true;
    }
    if !path.as_os_str().is_empty() {
        if let Ok(exe) = std::env::current_exe() {
            if path_starts_with_for_policy(&exe, path) {
                return true;
            }
        }
    }
    false
}

fn scan_macos_apps_and_orphans(
    dedup: &HardlinkDeduplicator,
    min_orphan_days: u32,
    now_secs: i64,
    cancel: &AtomicBool,
) -> (Vec<InstalledAppEntry>, Vec<OrphanResidue>) {
    let Some(home) = resolve_home_dir() else {
        return (Vec::new(), Vec::new());
    };

    // Discover user-removable .app bundles (CLEARLENS_APPS_DIR enables isolated Docker tests)
    let using_override = std::env::var_os("CLEARLENS_APPS_DIR").is_some();
    let app_dirs: Vec<PathBuf> = if let Some(override_dir) = std::env::var_os("CLEARLENS_APPS_DIR") {
        vec![PathBuf::from(override_dir)]
    } else {
        vec![PathBuf::from("/Applications"), home.join("Applications")]
    };

    let library = home.join("Library");
    let residue_roots = [
        ("Application Support", library.join("Application Support")),
        ("Caches", library.join("Caches")),
        ("Containers", library.join("Containers")),
        ("Saved Application State", library.join("Saved Application State")),
        ("Preferences", library.join("Preferences")),
        ("Logs", library.join("Logs")),
    ];

    let mut installed_tokens: HashSet<String> = HashSet::new();
    // Harvest tokens from macOS system apps and Homebrew Cask/Cellar so active tools are never flagged as orphans
    if !using_override {
        for ro_dir in [
            PathBuf::from("/System/Applications"),
            PathBuf::from("/System/Applications/Utilities"),
            PathBuf::from("/opt/homebrew/Caskroom"),
            PathBuf::from("/usr/local/Caskroom"),
            PathBuf::from("/opt/homebrew/Cellar"),
            PathBuf::from("/usr/local/Cellar"),
        ] {
            harvest_dir_tokens(&ro_dir, &mut installed_tokens);
        }
    }
    let ignore_paths = load_app_config().ignore_paths;
    let mut apps = Vec::new();

    for dir in app_dirs {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) != Some("app") {
                continue;
            }
            let Ok(app_meta) = inspect_path_meta(&p) else {
                continue;
            };
            if !app_meta.is_dir || app_meta.is_symlink_or_reparse {
                continue;
            }
            let default_name = p
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "Unknown".to_string());
            let plist_path = p.join("Contents").join("Info.plist");
            let (bundle_id, plist_name) = parse_info_plist(&plist_path);
            let name = plist_name.unwrap_or(default_name);

            let mut tokens = Vec::new();
            tokens.push(normalize_token(&name));
            if let Some(ref bid) = bundle_id {
                tokens.push(bid.to_ascii_lowercase());
                if let Some(last) = bid.rsplit('.').next() {
                    if last.len() >= 3 {
                        tokens.push(normalize_token(last));
                    }
                }
            }
            for tok in &tokens {
                if tok.len() >= 3 {
                    installed_tokens.insert(tok.clone());
                }
            }

            if is_clearlens_self_app(&name, bundle_id.as_deref(), &p)
                || is_path_ignored(&p, &ignore_paths)
            {
                continue;
            }

            let app_bytes = measure_dir_physical(&p, dedup).0;
            let mut residues = Vec::new();
            let mut residue_bytes = 0u64;

            for (kind, rroot) in &residue_roots {
                let Ok(rd) = fs::read_dir(rroot) else {
                    continue;
                };
                for re in rd.flatten() {
                    let rp = re.path();
                    if is_path_ignored(&rp, &ignore_paths)
                        || dir_contains_ignored(&rp, &ignore_paths)
                    {
                        continue;
                    }
                    let rname = re.file_name().to_string_lossy().to_string();
                    if matches_app_tokens(&rname, &tokens) && ProtectedBlocklist::check_path(&rp).is_ok() {
                        let (b, f) = measure_entry_physical(&rp, dedup);
                        if b > 0 {
                            residue_bytes = residue_bytes.saturating_add(b);
                            residues.push(AppResidueItem {
                                path: rp,
                                kind: (*kind).to_string(),
                                allocated_bytes: b,
                                file_count: f,
                            });
                        }
                    }
                }
            }

            apps.push(InstalledAppEntry {
                name,
                bundle_id,
                install_path: p,
                app_bytes,
                residue_bytes,
                residues,
            });
        }
    }

    apps.sort_by(|a, b| (b.app_bytes + b.residue_bytes).cmp(&(a.app_bytes + a.residue_bytes)));

    // Orphan Residue Hunter across ~/Library/{Application Support, Caches, Containers, Saved Application State}
    let orphan_roots = [
        ("Application Support", library.join("Application Support")),
        ("Caches", library.join("Caches")),
        ("Containers", library.join("Containers")),
        ("Saved Application State", library.join("Saved Application State")),
    ];

    let orphans = detect_orphans(
        &orphan_roots,
        &installed_tokens,
        dedup,
        min_orphan_days,
        now_secs,
        cancel,
    );

    (apps, orphans)
}

fn scan_windows_apps_and_orphans(
    dedup: &HardlinkDeduplicator,
    min_orphan_days: u32,
    now_secs: i64,
    cancel: &AtomicBool,
) -> (Vec<InstalledAppEntry>, Vec<OrphanResidue>) {
    let Some(home) = resolve_home_dir() else {
        return (Vec::new(), Vec::new());
    };
    let local_appdata = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join("AppData/Local"));
    let roaming_appdata = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join("AppData/Roaming"));

    // Only user-space `%LOCALAPPDATA%/Programs` (or `CLEARLENS_APPS_DIR`) entries are listed as
    // directly removable app bundles; `%PROGRAMFILES%` and `%PROGRAMFILES(X86)%` are scanned
    // read-only into `installed_tokens` so MSI/system installs are never dragged to Trash or flagged as orphans.
    let using_override = std::env::var_os("CLEARLENS_APPS_DIR").is_some();
    let install_roots: Vec<PathBuf> = if let Some(override_dir) = std::env::var_os("CLEARLENS_APPS_DIR") {
        vec![PathBuf::from(override_dir)]
    } else {
        vec![local_appdata.join("Programs")]
    };

    let residue_roots = [
        ("AppData/Roaming", roaming_appdata.clone()),
        ("AppData/Local", local_appdata.clone()),
    ];

    let mut installed_tokens = HashSet::new();
    if !using_override {
        for sys_var in ["PROGRAMFILES", "PROGRAMFILES(X86)"] {
            if let Some(pf) = std::env::var_os(sys_var) {
                harvest_dir_tokens(&PathBuf::from(pf), &mut installed_tokens);
            }
        }
    }
    let ignore_paths = load_app_config().ignore_paths;
    let mut apps = Vec::new();

    for root in install_roots {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let Ok(entries) = fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            let Ok(app_meta) = inspect_path_meta(&p) else {
                continue;
            };
            if !app_meta.is_dir || app_meta.is_symlink_or_reparse {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if is_windows_shared_or_system_dir(&name) {
                continue;
            }
            let norm = normalize_token(&name);
            if norm.len() >= 3 {
                installed_tokens.insert(norm.clone());
            }
            if is_clearlens_self_app(&name, None, &p) || is_path_ignored(&p, &ignore_paths) {
                continue;
            }
            let app_bytes = measure_dir_physical(&p, dedup).0;
            let tokens = vec![norm];

            let mut residues = Vec::new();
            let mut residue_bytes = 0u64;
            for (kind, rroot) in &residue_roots {
                let Ok(rd) = fs::read_dir(rroot) else {
                    continue;
                };
                for re in rd.flatten() {
                    let rp = re.path();
                    if is_path_ignored(&rp, &ignore_paths)
                        || dir_contains_ignored(&rp, &ignore_paths)
                    {
                        continue;
                    }
                    let rname = re.file_name().to_string_lossy().to_string();
                    if matches_app_tokens(&rname, &tokens) && ProtectedBlocklist::check_path(&rp).is_ok() {
                        let (b, f) = measure_entry_physical(&rp, dedup);
                        if b > 0 {
                            residue_bytes = residue_bytes.saturating_add(b);
                            residues.push(AppResidueItem {
                                path: rp,
                                kind: (*kind).to_string(),
                                allocated_bytes: b,
                                file_count: f,
                            });
                        }
                    }
                }
            }

            apps.push(InstalledAppEntry {
                name,
                bundle_id: None,
                install_path: p,
                app_bytes,
                residue_bytes,
                residues,
            });
        }
    }

    apps.sort_by(|a, b| (b.app_bytes + b.residue_bytes).cmp(&(a.app_bytes + a.residue_bytes)));
    let orphans = detect_orphans(
        &residue_roots,
        &installed_tokens,
        dedup,
        min_orphan_days,
        now_secs,
        cancel,
    );
    (apps, orphans)
}

fn scan_linux_apps_and_orphans(
    dedup: &HardlinkDeduplicator,
    min_orphan_days: u32,
    now_secs: i64,
    cancel: &AtomicBool,
) -> (Vec<InstalledAppEntry>, Vec<OrphanResidue>) {
    let Some(home) = resolve_home_dir() else {
        return (Vec::new(), Vec::new());
    };
    let mut installed_tokens = HashSet::new();
    let mut apps = Vec::new();

    let using_override = std::env::var_os("CLEARLENS_APPS_DIR").is_some();
    if !using_override {
        harvest_dir_tokens(Path::new("/usr/share/applications"), &mut installed_tokens);
    }

    let desktop_dirs = if let Some(override_dir) = std::env::var_os("CLEARLENS_APPS_DIR") {
        vec![PathBuf::from(override_dir)]
    } else {
        vec![home.join(".local/share/applications")]
    };

    for dir in desktop_dirs {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) != Some("desktop") {
                continue;
            }
            let stem = p
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            let norm = normalize_token(&stem);
            if norm.len() >= 3 {
                installed_tokens.insert(norm);
            }
            if is_clearlens_self_app(&stem, None, &p) {
                continue;
            }
            apps.push(InstalledAppEntry {
                name: stem,
                bundle_id: None,
                install_path: p,
                app_bytes: 0,
                residue_bytes: 0,
                residues: Vec::new(),
            });
        }
    }

    let orphan_roots = [
        ("~/.cache", home.join(".cache")),
        ("~/.config", home.join(".config")),
    ];
    let orphans = detect_orphans(
        &orphan_roots,
        &installed_tokens,
        dedup,
        min_orphan_days,
        now_secs,
        cancel,
    );
    (apps, orphans)
}

fn detect_orphans(
    roots: &[(&str, PathBuf)],
    installed_tokens: &HashSet<String>,
    dedup: &HardlinkDeduplicator,
    min_orphan_days: u32,
    now_secs: i64,
    cancel: &AtomicBool,
) -> Vec<OrphanResidue> {
    let ignore_paths = crate::config::load_app_config().ignore_paths;
    let mut orphans = Vec::new();
    for (kind, root) in roots {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let Ok(entries) = fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if crate::config::is_path_ignored(&p, &ignore_paths)
                || crate::config::dir_contains_ignored(&p, &ignore_paths)
            {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') || is_allowlisted_system_entry(&name) {
                continue;
            }
            if ProtectedBlocklist::check_path(&p).is_err() {
                continue;
            }
            let Ok(meta) = inspect_path_meta(&p) else {
                continue;
            };
            if !meta.is_dir || meta.is_symlink_or_reparse || meta.is_cloud_placeholder {
                continue;
            }

            let lower_name = name.to_ascii_lowercase();
            let norm_name = normalize_token(&name);
            let is_installed = installed_tokens.iter().any(|tok| {
                lower_name == *tok
                    || norm_name == *tok
                    || (tok.len() >= 4 && lower_name.contains(tok))
                    || (tok.len() == 3
                        && (lower_name.starts_with(&format!("{tok}."))
                            || lower_name.ends_with(&format!(".{tok}"))))
                    || (norm_name.len() >= 4 && tok.contains(&norm_name))
            });
            if is_installed {
                continue;
            }

            let newest_mtime = newest_dir_mtime(&p).max(meta.mtime_secs);
            let inactive_days = if now_secs > newest_mtime && newest_mtime > 0 {
                ((now_secs - newest_mtime) / 86_400) as u64
            } else {
                0
            };
            if inactive_days < min_orphan_days as u64 {
                continue;
            }

            let (bytes, files) = measure_dir_physical(&p, dedup);
            if bytes > 0 && files > 0 {
                orphans.push(OrphanResidue {
                    name,
                    path: p,
                    location_kind: (*kind).to_string(),
                    allocated_bytes: bytes,
                    file_count: files,
                    last_modified_ts: newest_mtime,
                    inactive_days,
                });
            }
        }
    }

    orphans.sort_by(|a, b| b.allocated_bytes.cmp(&a.allocated_bytes));
    orphans
}

fn harvest_dir_tokens(dir: &Path, out: &mut HashSet<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let stem = name
            .strip_suffix(".app")
            .or_else(|| name.strip_suffix(".desktop"))
            .unwrap_or(&name);
        let norm = normalize_token(stem);
        if norm.len() >= 3 {
            out.insert(norm);
        }
    }
}

fn is_windows_shared_or_system_dir(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "common files"
            | "internet explorer"
            | "modifiablewindowsapps"
            | "reference assemblies"
            | "uninstall information"
            | "windows defender"
            | "windows defender advanced threat protection"
            | "windows mail"
            | "windows media player"
            | "windows multimediaplatform"
            | "windows nt"
            | "windows photo viewer"
            | "windows portable devices"
            | "windows security"
            | "windows sidebar"
            | "windowspowershell"
    ) || lower.starts_with("microsoft")
}

fn is_allowlisted_system_entry(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SYSTEM_ORPHAN_ALLOWLIST
        .iter()
        .any(|prefix| lower == *prefix || lower.starts_with(prefix))
}

fn matches_app_tokens(entry_name: &str, app_tokens: &[String]) -> bool {
    let lower = entry_name.to_ascii_lowercase();
    let stem = lower
        .strip_suffix(".plist")
        .or_else(|| lower.strip_suffix(".savedstate"))
        .unwrap_or(&lower);
    let norm = normalize_token(stem);
    app_tokens.iter().any(|tok| {
        if tok.len() < 3 {
            return false;
        }
        stem == tok
            || norm == *tok
            || stem.starts_with(&format!("{tok}."))
            || stem.ends_with(&format!(".{tok}"))
    })
}

fn normalize_token(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn measure_entry_physical(path: &Path, dedup: &HardlinkDeduplicator) -> (u64, u64) {
    let Ok(meta) = inspect_path_meta(path) else {
        return (0, 0);
    };
    if meta.is_symlink_or_reparse || meta.is_cloud_placeholder {
        return (0, 0);
    }
    if meta.is_dir {
        measure_dir_physical(path, dedup)
    } else if dedup.should_count(meta.dev, meta.ino, meta.nlink) {
        (meta.allocated_bytes, 1)
    } else {
        (0, 0)
    }
}

fn newest_dir_mtime(dir: &Path) -> i64 {
    let mut newest = inspect_path_meta(dir).map(|m| m.mtime_secs).unwrap_or(0);
    let Ok(entries) = fs::read_dir(dir) else {
        return newest;
    };
    for entry in entries.flatten().take(200) {
        if let Ok(m) = inspect_path_meta(&entry.path()) {
            newest = newest.max(m.mtime_secs);
        }
    }
    newest
}

/// Lightweight pure-Rust XML Info.plist extractor for CFBundleIdentifier & CFBundleName.
fn parse_info_plist(path: &Path) -> (Option<String>, Option<String>) {
    let Ok(raw) = fs::read_to_string(path) else {
        return (None, None);
    };
    let bid = extract_plist_string(&raw, "CFBundleIdentifier");
    let display = extract_plist_string(&raw, "CFBundleDisplayName")
        .or_else(|| extract_plist_string(&raw, "CFBundleName"));
    (bid, display)
}

fn extract_plist_string(xml: &str, key: &str) -> Option<String> {
    let needle = format!("<key>{key}</key>");
    let start = xml.find(&needle)? + needle.len();
    let rest = &xml[start..];
    let str_open = rest.find("<string>")? + "<string>".len();
    let after = &rest[str_open..];
    let str_close = after.find("</string>")?;
    let val = after[..str_close].trim();
    if val.is_empty() {
        None
    } else {
        Some(val.to_string())
    }
}
