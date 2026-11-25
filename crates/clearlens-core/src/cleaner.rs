use crate::audit::append_audit_record;
use crate::config::{dir_contains_ignored, is_path_ignored, load_app_config, paths_equal_for_policy};
use crate::models::{
    AuditRecord, CleanItemOutcome, CleanItemRequest, CleanReport, DeleteMode, RiskLevel,
};
use crate::platform::{inspect_path_meta, move_to_os_trash, resolve_home_dir};
use crate::rules::glob_engine::is_excluded;
use crate::rules::smart_scanners::parse_docker_size;
use crate::rules::{build_clean_policies, RuleCleanPolicy};
use crate::safety::{
    is_metadata_reparse_or_symlink, normalize_slashes, HardlinkDeduplicator, ProtectedBlocklist,
};
use chrono::Utc;
use globset::GlobSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub fn execute_clean(items: &[CleanItemRequest], dry_run: bool) -> CleanReport {
    let start = Instant::now();
    let dedup = HardlinkDeduplicator::default();
    let policies = build_clean_policies();
    let ignore_paths = load_app_config().ignore_paths;
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut outcomes = Vec::with_capacity(items.len());
    let mut total_freed_bytes = 0u64;
    let mut succeeded_count = 0usize;
    let mut failed_count = 0usize;

    for item in items {
        let policy: Option<&RuleCleanPolicy> = policies.get(&item.rule_id);

        // Enforce authoritative rule risk & delete mode so callers can never downgrade Trash -> Permanent
        let effective_risk = if item.rule_id == "ai.ollama_models"
            || item.rule_id.starts_with("duplicates.")
            || item.rule_id.starts_with("uninstaller.")
            || item.rule_id.starts_with("lens.")
        {
            RiskLevel::ReviewRequired
        } else if let Some(p) = policy {
            item.risk.max(p.risk)
        } else {
            item.risk
        };

        let actual_mode = if effective_risk == RiskLevel::ReviewRequired
            || policy
                .map(|p| p.delete_mode == DeleteMode::Trash)
                .unwrap_or(false)
        {
            DeleteMode::Trash
        } else if let Some(p) = policy {
            if p.delete_mode == DeleteMode::NativeCommand {
                DeleteMode::NativeCommand
            } else {
                item.delete_mode
            }
        } else {
            item.delete_mode
        };

        if actual_mode == DeleteMode::NativeCommand {
            let outcome = run_native_clean(item, dry_run);
            if outcome.success {
                succeeded_count += 1;
                total_freed_bytes = total_freed_bytes.saturating_add(outcome.freed_bytes);
            } else {
                failed_count += 1;
            }
            outcomes.push(outcome);
            continue;
        }

        if let Err(err) = ProtectedBlocklist::check_path(&item.path) {
            failed_count += 1;
            outcomes.push(CleanItemOutcome {
                rule_id: item.rule_id.clone(),
                path: item.path.clone(),
                requested_mode: item.delete_mode,
                actual_mode,
                freed_bytes: 0,
                success: false,
                error: Some(err.to_string()),
            });
            continue;
        }

        if is_path_ignored(&item.path, &ignore_paths) {
            failed_count += 1;
            outcomes.push(CleanItemOutcome {
                rule_id: item.rule_id.clone(),
                path: item.path.clone(),
                requested_mode: item.delete_mode,
                actual_mode,
                freed_bytes: 0,
                success: false,
                error: Some("skipped: path is protected by ignore whitelist".to_string()),
            });
            continue;
        }

        // P0.1: Reference-counted Ollama blob GC (reclaims manifest + ref_count==1 blobs into Trash)
        if item.rule_id == "ai.ollama_models" {
            match crate::rules::ollama_gc::clean_ollama_model(&item.path, dry_run) {
                Ok(gc) => {
                    succeeded_count += 1;
                    total_freed_bytes = total_freed_bytes.saturating_add(gc.freed_bytes);
                    outcomes.push(CleanItemOutcome {
                        rule_id: item.rule_id.clone(),
                        path: item.path.clone(),
                        requested_mode: item.delete_mode,
                        actual_mode: DeleteMode::Trash,
                        freed_bytes: gc.freed_bytes,
                        success: true,
                        error: None,
                    });
                }
                Err(err_msg) => {
                    failed_count += 1;
                    outcomes.push(CleanItemOutcome {
                        rule_id: item.rule_id.clone(),
                        path: item.path.clone(),
                        requested_mode: item.delete_mode,
                        actual_mode: DeleteMode::Trash,
                        freed_bytes: 0,
                        success: false,
                        error: Some(err_msg),
                    });
                }
            }
            continue;
        }

        let Ok(meta) = inspect_path_meta(&item.path) else {
            failed_count += 1;
            outcomes.push(CleanItemOutcome {
                rule_id: item.rule_id.clone(),
                path: item.path.clone(),
                requested_mode: item.delete_mode,
                actual_mode,
                freed_bytes: 0,
                success: false,
                error: Some("path no longer exists or is unreadable".to_string()),
            });
            continue;
        };

        if meta.is_symlink_or_reparse {
            failed_count += 1;
            outcomes.push(CleanItemOutcome {
                rule_id: item.rule_id.clone(),
                path: item.path.clone(),
                requested_mode: item.delete_mode,
                actual_mode,
                freed_bytes: 0,
                success: false,
                error: Some("refusing to traverse or delete symlink or reparse target".to_string()),
            });
            continue;
        }

        let cutoff_secs = policy.and_then(|p| {
            if p.min_age_days > 0 {
                Some(now_secs - (p.min_age_days as i64) * 86_400)
            } else {
                None
            }
        });
        let empty_exclude: Option<GlobSet> = None;
        let exclude_set = policy.map(|p| &p.exclude_set).unwrap_or(&empty_exclude);

        // Re-verify exclude & age guardrails right before acting on single files (anti-TOCTOU)
        if !meta.is_dir {
            if is_excluded(exclude_set, &item.path) {
                failed_count += 1;
                outcomes.push(CleanItemOutcome {
                    rule_id: item.rule_id.clone(),
                    path: item.path.clone(),
                    requested_mode: item.delete_mode,
                    actual_mode,
                    freed_bytes: 0,
                    success: false,
                    error: Some("skipped: path matched rule exclude filter".to_string()),
                });
                continue;
            }
            if let Some(cutoff) = cutoff_secs {
                if meta.mtime_secs > cutoff {
                    failed_count += 1;
                    outcomes.push(CleanItemOutcome {
                        rule_id: item.rule_id.clone(),
                        path: item.path.clone(),
                        requested_mode: item.delete_mode,
                        actual_mode,
                        freed_bytes: 0,
                        success: false,
                        error: Some("skipped: file was modified recently after scan".to_string()),
                    });
                    continue;
                }
            }
        }

        let has_inner_ignore = meta.is_dir && dir_contains_ignored(&item.path, &ignore_paths);
        let preserve_root = meta.is_dir
            && (has_inner_ignore
                || is_preserved_container_root(&item.path)
                || policy
                    .map(|p| p.anchor_dirs.iter().any(|a| paths_equal_for_policy(a, &item.path)))
                    .unwrap_or(false));

        let estimated_bytes = if meta.is_dir {
            measure_filtered_dir_physical(
                &item.path,
                cutoff_secs,
                exclude_set,
                &ignore_paths,
                &dedup,
            )
        } else {
            meta.allocated_bytes
        };

        if dry_run {
            succeeded_count += 1;
            total_freed_bytes = total_freed_bytes.saturating_add(estimated_bytes);
            outcomes.push(CleanItemOutcome {
                rule_id: item.rule_id.clone(),
                path: item.path.clone(),
                requested_mode: item.delete_mode,
                actual_mode,
                freed_bytes: estimated_bytes,
                success: true,
                error: None,
            });
            continue;
        }

        let res = match actual_mode {
            DeleteMode::Trash => {
                if meta.is_dir
                    && (preserve_root
                        || dir_has_any_filtered_out_entry(
                            &item.path,
                            cutoff_secs,
                            exclude_set,
                            &ignore_paths,
                        ))
                {
                    trash_dir_contents_filtered(&item.path, cutoff_secs, exclude_set, &ignore_paths)
                } else {
                    move_to_os_trash(&item.path).map(|()| estimated_bytes)
                }
            }
            DeleteMode::Permanent => safe_remove_tree(
                &item.path,
                preserve_root,
                cutoff_secs,
                exclude_set,
                &ignore_paths,
                meta.dev,
            )
            .map(|(_, bytes)| bytes)
            .map_err(|e| e.to_string()),
            DeleteMode::NativeCommand => unreachable!(),
        };

        match res {
            Ok(actual_freed) => {
                succeeded_count += 1;
                total_freed_bytes = total_freed_bytes.saturating_add(actual_freed);
                let _ = append_audit_record(&AuditRecord {
                    timestamp: Utc::now().to_rfc3339(),
                    rule_id: item.rule_id.clone(),
                    path: item.path.clone(),
                    bytes_freed: actual_freed,
                    method: match actual_mode {
                        DeleteMode::Trash => "trash".to_string(),
                        DeleteMode::Permanent => "permanent".to_string(),
                        DeleteMode::NativeCommand => "native_command".to_string(),
                    },
                    success: true,
                    note: None,
                });
                outcomes.push(CleanItemOutcome {
                    rule_id: item.rule_id.clone(),
                    path: item.path.clone(),
                    requested_mode: item.delete_mode,
                    actual_mode,
                    freed_bytes: actual_freed,
                    success: true,
                    error: None,
                });
            }
            Err(err_msg) => {
                failed_count += 1;
                outcomes.push(CleanItemOutcome {
                    rule_id: item.rule_id.clone(),
                    path: item.path.clone(),
                    requested_mode: item.delete_mode,
                    actual_mode,
                    freed_bytes: 0,
                    success: false,
                    error: Some(err_msg),
                });
            }
        }
    }

    CleanReport {
        dry_run,
        duration_ms: start.elapsed().as_millis() as u64,
        total_freed_bytes,
        succeeded_count,
        failed_count,
        outcomes,
    }
}

/// Runs normal user-level cleanup first and, if any `requires_elevation` rules fail due to
/// permission denied, prompts once via OS-native on-demand elevation (`invoke_elevated_clean`).
pub fn execute_clean_with_elevation(items: &[CleanItemRequest], dry_run: bool) -> CleanReport {
    let mut report = execute_clean(items, dry_run);
    if dry_run
        || report.failed_count == 0
        || std::env::var_os("CLEARLENS_IN_ELEVATED_WORKER").is_some()
    {
        return report;
    }

    let policies = build_clean_policies();
    let mut retry_indices = Vec::new();
    let mut retry_items = Vec::new();

    for (idx, (item, outcome)) in items.iter().zip(report.outcomes.iter()).enumerate() {
        if outcome.success {
            continue;
        }
        let allows_elev = policies
            .get(&item.rule_id)
            .map(|p| p.requires_elevation)
            .unwrap_or(false);
        if !allows_elev {
            continue;
        }
        let err_lower = outcome
            .error
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();
        if err_lower.contains("permission denied")
            || err_lower.contains("access is denied")
            || err_lower.contains("os error 13")
            || err_lower.contains("os error 5")
        {
            retry_indices.push(idx);
            retry_items.push(item.clone());
        }
    }

    if retry_items.is_empty() {
        return report;
    }

    if let Ok(elev_rep) = crate::platform::elevation::invoke_elevated_clean(&retry_items, false) {
        if elev_rep.outcomes.len() == retry_indices.len() {
            for (orig_idx, new_outcome) in retry_indices.into_iter().zip(elev_rep.outcomes) {
                report.outcomes[orig_idx] = new_outcome;
            }
            report.succeeded_count = report.outcomes.iter().filter(|o| o.success).count();
            report.failed_count = report.outcomes.iter().filter(|o| !o.success).count();
            report.total_freed_bytes = report
                .outcomes
                .iter()
                .filter(|o| o.success)
                .fold(0u64, |acc, o| acc.saturating_add(o.freed_bytes));
        }
    }

    report
}

/// Returns true if `path` is a system/user container directory whose contents may be cleaned
/// (`%TEMP%`, `/tmp`, `~/Library/Logs`, `~/Library/Caches`), but the root directory itself must stay intact.
fn is_preserved_container_root(path: &Path) -> bool {
    let norm = normalize_slashes(&path.to_string_lossy())
        .trim_end_matches('/')
        .to_ascii_lowercase();
    if matches!(
        norm.as_str(),
        "/tmp" | "/private/tmp" | "/var/tmp" | "/private/var/tmp" | "c:/windows/temp" | "c:/windows/softwaredistribution/download"
    ) {
        return true;
    }
    let env_temp = normalize_slashes(&std::env::temp_dir().to_string_lossy())
        .trim_end_matches('/')
        .to_ascii_lowercase();
    if !env_temp.is_empty() && norm == env_temp {
        return true;
    }
    if let Some(home) = resolve_home_dir() {
        let h = normalize_slashes(&home.to_string_lossy())
            .trim_end_matches('/')
            .to_ascii_lowercase();
        for suffix in [
            "library/logs",
            "library/caches",
            "library/caches/temporaryitems",
            "appdata/local/temp",
            "appdata/local/logs",
            "appdata/local/crashdumps",
            ".cache",
        ] {
            if norm == format!("{h}/{suffix}") {
                return true;
            }
        }
    }
    false
}

fn measure_filtered_dir_physical(
    dir: &Path,
    cutoff_secs: Option<i64>,
    exclude_set: &Option<GlobSet>,
    ignore_paths: &[PathBuf],
    dedup: &HardlinkDeduplicator,
) -> u64 {
    if is_excluded(exclude_set, dir)
        || is_path_ignored(dir, ignore_paths)
        || ProtectedBlocklist::check_path(dir).is_err()
    {
        return 0;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return 0;
    };
    let mut total = 0u64;
    for entry in rd.flatten() {
        let p = entry.path();
        if is_excluded(exclude_set, &p)
            || is_path_ignored(&p, ignore_paths)
            || ProtectedBlocklist::check_path(&p).is_err()
        {
            continue;
        }
        let Ok(meta) = inspect_path_meta(&p) else {
            continue;
        };
        if meta.is_symlink_or_reparse || meta.is_cloud_placeholder {
            continue;
        }
        if meta.is_dir {
            total = total.saturating_add(measure_filtered_dir_physical(
                &p,
                cutoff_secs,
                exclude_set,
                ignore_paths,
                dedup,
            ));
        } else {
            if let Some(cutoff) = cutoff_secs {
                if meta.mtime_secs > cutoff {
                    continue;
                }
            }
            if dedup.should_count(meta.dev, meta.ino, meta.nlink) {
                total = total.saturating_add(meta.allocated_bytes);
            }
        }
    }
    total
}

fn dir_has_any_filtered_out_entry(
    dir: &Path,
    cutoff_secs: Option<i64>,
    exclude_set: &Option<GlobSet>,
    ignore_paths: &[PathBuf],
) -> bool {
    if dir_contains_ignored(dir, ignore_paths) {
        return true;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return true;
    };
    for entry in rd.flatten() {
        let child = entry.path();
        if is_excluded(exclude_set, &child)
            || is_path_ignored(&child, ignore_paths)
            || ProtectedBlocklist::check_path(&child).is_err()
        {
            return true;
        }
        let Ok(cmeta) = inspect_path_meta(&child) else {
            continue;
        };
        if cmeta.is_symlink_or_reparse || cmeta.is_cloud_placeholder {
            return true;
        }
        if cmeta.is_dir {
            if dir_has_any_filtered_out_entry(&child, cutoff_secs, exclude_set, ignore_paths) {
                return true;
            }
        } else if let Some(cutoff) = cutoff_secs {
            if cmeta.mtime_secs > cutoff {
                return true;
            }
        }
    }
    false
}

fn trash_dir_contents_filtered(
    dir: &Path,
    cutoff_secs: Option<i64>,
    exclude_set: &Option<GlobSet>,
    ignore_paths: &[PathBuf],
) -> Result<u64, String> {
    ProtectedBlocklist::check_path(dir).map_err(|e| e.to_string())?;
    if is_path_ignored(dir, ignore_paths) {
        return Ok(0);
    }
    let rd = fs::read_dir(dir).map_err(|e| e.to_string())?;
    let mut freed = 0u64;
    let dedup = HardlinkDeduplicator::default();
    for entry in rd.flatten() {
        let child = entry.path();
        if is_excluded(exclude_set, &child)
            || is_path_ignored(&child, ignore_paths)
            || ProtectedBlocklist::check_path(&child).is_err()
        {
            continue;
        }
        let Ok(cmeta) = inspect_path_meta(&child) else {
            continue;
        };
        if cmeta.is_symlink_or_reparse || cmeta.is_cloud_placeholder {
            continue;
        }
        if cmeta.is_dir {
            if dir_contains_ignored(&child, ignore_paths)
                || dir_has_any_filtered_out_entry(&child, cutoff_secs, exclude_set, ignore_paths)
            {
                let sub_freed =
                    trash_dir_contents_filtered(&child, cutoff_secs, exclude_set, ignore_paths)?;
                freed = freed.saturating_add(sub_freed);
            } else {
                let bytes = measure_filtered_dir_physical(
                    &child,
                    cutoff_secs,
                    exclude_set,
                    ignore_paths,
                    &dedup,
                );
                move_to_os_trash(&child)?;
                freed = freed.saturating_add(bytes);
            }
        } else {
            if let Some(cutoff) = cutoff_secs {
                if cmeta.mtime_secs > cutoff {
                    continue;
                }
            }
            move_to_os_trash(&child)?;
            freed = freed.saturating_add(cmeta.allocated_bytes);
        }
    }
    Ok(freed)
}

/// Safely removes a file or directory tree WITHOUT ever descending into symlinked/reparse
/// subdirectories or crossing filesystem mount boundaries (`xdev`), re-checking `ProtectedBlocklist`,
/// `exclude_set`, `ignore_paths`, and `cutoff_secs` at deletion time (anti-TOCTOU).
/// Returns `(all_removed, freed_bytes)`. When `preserve_root` is true, cleans inside `path` without removing `path`.
fn safe_remove_tree(
    path: &Path,
    preserve_root: bool,
    cutoff_secs: Option<i64>,
    exclude_set: &Option<GlobSet>,
    ignore_paths: &[PathBuf],
    root_dev: u64,
) -> std::io::Result<(bool, u64)> {
    ProtectedBlocklist::check_path(path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e.to_string()))?;
    if !preserve_root && (is_excluded(exclude_set, path) || is_path_ignored(path, ignore_paths)) {
        return Ok((false, 0));
    }

    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        // Unlink the symlink entry itself, never follow into target
        #[cfg(windows)]
        {
            if meta.is_dir() {
                fs::remove_dir(path)?;
            } else {
                fs::remove_file(path)?;
            }
        }
        #[cfg(not(windows))]
        {
            fs::remove_file(path)?;
        }
        return Ok((true, 0));
    }
    if is_metadata_reparse_or_symlink(&meta) {
        return Ok((false, 0));
    }

    if meta.is_dir() {
        let mut all_children_removed = true;
        let mut freed_bytes = 0u64;
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let child = entry.path();
            if is_excluded(exclude_set, &child)
                || is_path_ignored(&child, ignore_paths)
                || ProtectedBlocklist::check_path(&child).is_err()
            {
                all_children_removed = false;
                continue;
            }
            let cmeta = fs::symlink_metadata(&child)?;
            if cmeta.file_type().is_symlink() {
                // Unlink symlink file without touching symlink target
                #[cfg(windows)]
                {
                    if cmeta.is_dir() {
                        fs::remove_dir(&child)?;
                    } else {
                        fs::remove_file(&child)?;
                    }
                }
                #[cfg(not(windows))]
                {
                    fs::remove_file(&child)?;
                }
            } else if is_metadata_reparse_or_symlink(&cmeta) {
                // Non-symlink NTFS volume mount point or custom reparse dir: never descend or delete
                all_children_removed = false;
                continue;
            } else if cmeta.is_dir() {
                if let Ok(child_pmeta) = inspect_path_meta(&child) {
                    if root_dev != 0 && child_pmeta.dev != 0 && child_pmeta.dev != root_dev {
                        // Never cross filesystem / bind-mount boundaries during deletion
                        all_children_removed = false;
                        continue;
                    }
                }
                let child_preserve = dir_contains_ignored(&child, ignore_paths);
                let (sub_removed, sub_bytes) = safe_remove_tree(
                    &child,
                    child_preserve,
                    cutoff_secs,
                    exclude_set,
                    ignore_paths,
                    root_dev,
                )?;
                freed_bytes = freed_bytes.saturating_add(sub_bytes);
                if !sub_removed || child_preserve {
                    all_children_removed = false;
                }
            } else {
                if let Ok(pmeta) = inspect_path_meta(&child) {
                    if pmeta.is_cloud_placeholder {
                        all_children_removed = false;
                        continue;
                    }
                    if let Some(cutoff) = cutoff_secs {
                        if pmeta.mtime_secs > cutoff {
                            all_children_removed = false;
                            continue;
                        }
                    }
                    freed_bytes = freed_bytes.saturating_add(pmeta.allocated_bytes);
                }
                fs::remove_file(&child)?;
            }
        }

        if !preserve_root && all_children_removed {
            fs::remove_dir(path)?;
            Ok((true, freed_bytes))
        } else {
            Ok((false, freed_bytes))
        }
    } else {
        let mut file_bytes = 0u64;
        if let Ok(pmeta) = inspect_path_meta(path) {
            if pmeta.is_cloud_placeholder {
                return Ok((false, 0));
            }
            if let Some(cutoff) = cutoff_secs {
                if pmeta.mtime_secs > cutoff {
                    return Ok((false, 0));
                }
            }
            file_bytes = pmeta.allocated_bytes;
        }
        fs::remove_file(path)?;
        Ok((true, file_bytes))
    }
}

fn run_native_clean(item: &CleanItemRequest, dry_run: bool) -> CleanItemOutcome {
    let cmd_str = item.native_command.clone().unwrap_or_default();
    if dry_run {
        return CleanItemOutcome {
            rule_id: item.rule_id.clone(),
            path: item.path.clone(),
            requested_mode: item.delete_mode,
            actual_mode: DeleteMode::NativeCommand,
            freed_bytes: 0,
            success: true,
            error: None,
        };
    }

    if item.rule_id == "dev.docker_prune"
        && cmd_str.trim() == "docker builder prune -f && docker image prune -f"
    {
        let mut reclaimed_total = 0u64;
        let out1 = Command::new("docker").args(["builder", "prune", "-f"]).output();
        let out2 = Command::new("docker").args(["image", "prune", "-f"]).output();

        let mut any_ok = false;
        for out in [&out1, &out2] {
            if let Ok(o) = out {
                if o.status.success() {
                    any_ok = true;
                    let text = String::from_utf8_lossy(&o.stdout);
                    for line in text.lines() {
                        if let Some(rest) = line.trim().strip_prefix("Total reclaimed space:") {
                            reclaimed_total =
                                reclaimed_total.saturating_add(parse_docker_size(rest.trim()));
                        }
                    }
                }
            }
        }

        if any_ok {
            let _ = append_audit_record(&AuditRecord {
                timestamp: Utc::now().to_rfc3339(),
                rule_id: item.rule_id.clone(),
                path: item.path.clone(),
                bytes_freed: reclaimed_total,
                method: "native_command".to_string(),
                success: true,
                note: Some("docker builder prune -f && docker image prune -f".to_string()),
            });
        }

        return CleanItemOutcome {
            rule_id: item.rule_id.clone(),
            path: item.path.clone(),
            requested_mode: item.delete_mode,
            actual_mode: DeleteMode::NativeCommand,
            freed_bytes: reclaimed_total,
            success: any_ok,
            error: if any_ok {
                None
            } else {
                Some("docker prune failed or daemon unavailable".to_string())
            },
        };
    }

    CleanItemOutcome {
        rule_id: item.rule_id.clone(),
        path: item.path.clone(),
        requested_mode: item.delete_mode,
        actual_mode: DeleteMode::NativeCommand,
        freed_bytes: 0,
        success: false,
        error: Some(format!("unsupported native command: {cmd_str}")),
    }
}
