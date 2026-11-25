use crate::models::{DeleteMode, RuleDef, RuleFile, ScanHit, ScanOptions};
use crate::platform::{inspect_path_meta, resolve_home_dir};
use crate::safety::{HardlinkDeduplicator, ProtectedBlocklist};
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn evaluate_smart_rule(
    rf: &RuleFile,
    rule: &RuleDef,
    options: &ScanOptions,
    dedup: &HardlinkDeduplicator,
    locked_by: Option<String>,
    cancel: &AtomicBool,
) -> Vec<ScanHit> {
    match rule.scanner.as_deref() {
        Some("cold_project_artifacts") => {
            scan_cold_project_artifacts(rf, rule, options, dedup, locked_by, cancel)
        }
        Some("ollama_models") => scan_ollama_models(rf, rule, options, dedup, locked_by),
        Some("huggingface_hub") => scan_huggingface_hub(rf, rule, options, dedup, locked_by),
        Some("docker_system_df") => scan_docker_system_df(rf, rule, locked_by),
        _ => Vec::new(),
    }
}

fn scan_cold_project_artifacts(
    rf: &RuleFile,
    rule: &RuleDef,
    options: &ScanOptions,
    dedup: &HardlinkDeduplicator,
    locked_by: Option<String>,
    cancel: &AtomicBool,
) -> Vec<ScanHit> {
    let roots = resolve_workspace_roots(options);
    if roots.is_empty() {
        return Vec::new();
    }

    let target_dirs: Vec<String> = rule
        .params
        .get("target_dirs")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_else(|| {
            vec![
                "node_modules".into(),
                "target".into(),
                ".venv".into(),
                ".next".into(),
                "dist".into(),
                "build".into(),
            ]
        });

    let manifests: Vec<String> = rule
        .params
        .get("manifest_markers")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_else(|| {
            vec![
                "package.json".into(),
                "Cargo.toml".into(),
                "pyproject.toml".into(),
                "Package.swift".into(),
                "go.mod".into(),
            ]
        });

    let stale_days = options.stale_days.max(1);
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let cutoff_secs = now_secs - (stale_days as i64) * 86_400;

    let mut project_dirs = Vec::new();
    for root in roots {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        discover_projects(
            &root,
            0,
            5,
            &target_dirs,
            &manifests,
            &options.ignore_paths,
            &mut project_dirs,
        );
    }

    project_dirs
        .into_par_iter()
        .filter(|_| !cancel.load(Ordering::Relaxed))
        .flat_map(|proj_dir| {
            let latest_source_mtime = newest_source_mtime(&proj_dir, &target_dirs);
            if latest_source_mtime > cutoff_secs {
                return Vec::new();
            }
            let proj_name = proj_dir
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "project".to_string());

            let mut proj_hits = Vec::new();
            for tname in &target_dirs {
                let artifact_path = proj_dir.join(tname);
                if crate::config::is_path_ignored(&artifact_path, &options.ignore_paths)
                    || crate::config::dir_contains_ignored(&artifact_path, &options.ignore_paths)
                    || ProtectedBlocklist::check_path(&artifact_path).is_err()
                {
                    continue;
                }
                let Ok(meta) = inspect_path_meta(&artifact_path) else {
                    continue;
                };
                if !meta.is_dir || meta.is_symlink_or_reparse {
                    continue;
                }
                let (bytes, files) = measure_dir_physical(&artifact_path, dedup);
                if files > 0 && bytes > 0 {
                    proj_hits.push(ScanHit {
                        id: format!("{}::{}", rule.id, artifact_path.display()),
                        rule_id: rule.id.clone(),
                        category: rf.category.clone(),
                        app_name: rf.app_name.clone(),
                        app_name_zh: rf.app_name_zh.clone(),
                        title: format!("{proj_name} / {tname} (inactive > {stale_days}d)"),
                        title_zh: format!("{proj_name} / {tname}（超 {stale_days} 天未活跃）"),
                        risk: rule.risk,
                        default_checked: rule.default_checked,
                        delete_mode: rule.delete_mode,
                        requires_elevation: false,
                        path: artifact_path,
                        allocated_bytes: bytes,
                        file_count: files,
                        last_modified_ts: latest_source_mtime,
                        impact_note: rule.impact_note.clone(),
                        impact_note_zh: rule.impact_note_zh.clone(),
                        locked_by_process: locked_by.clone(),
                        native_command: None,
                    });
                }
            }
            proj_hits
        })
        .collect()
}

fn resolve_workspace_roots(options: &ScanOptions) -> Vec<PathBuf> {
    if !options.workspace_roots.is_empty() {
        return options
            .workspace_roots
            .iter()
            .filter(|p| p.is_dir())
            .cloned()
            .collect();
    }
    let Some(home) = resolve_home_dir() else {
        return Vec::new();
    };
    ["Projects", "Developer", "Code", "Workspace", "repos", "GitHub"]
        .into_iter()
        .map(|name| home.join(name))
        .filter(|p| p.is_dir())
        .collect()
}

fn discover_projects(
    dir: &Path,
    depth: usize,
    max_depth: usize,
    skip_names: &[String],
    manifests: &[String],
    ignore_paths: &[PathBuf],
    out: &mut Vec<PathBuf>,
) {
    if depth > max_depth || crate::config::is_path_ignored(dir, ignore_paths) {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut subdirs = Vec::new();
    let mut has_manifest = false;
    for entry in entries.flatten() {
        let p = entry.path();
        if crate::config::is_path_ignored(&p, ignore_paths) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name == ".git" || skip_names.iter().any(|s| s == &name) {
            continue;
        }
        let Ok(meta) = inspect_path_meta(&p) else {
            continue;
        };
        if meta.is_symlink_or_reparse {
            continue;
        }
        if meta.is_dir {
            subdirs.push(p);
        } else if manifests.iter().any(|m| m == &name) {
            has_manifest = true;
        }
    }
    if has_manifest {
        out.push(dir.to_path_buf());
    }
    for sub in subdirs {
        discover_projects(
            &sub,
            depth + 1,
            max_depth,
            skip_names,
            manifests,
            ignore_paths,
            out,
        );
    }
}

fn newest_source_mtime(dir: &Path, skip_dirs: &[String]) -> i64 {
    let mut newest = inspect_path_meta(dir).map(|m| m.mtime_secs).unwrap_or(0);
    let mut stack = vec![(dir.to_path_buf(), 0usize)];
    while let Some((cur, depth)) = stack.pop() {
        if depth > 4 {
            continue;
        }
        let Ok(entries) = fs::read_dir(&cur) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == ".git" || skip_dirs.iter().any(|s| s == &name) {
                continue;
            }
            let p = entry.path();
            let Ok(meta) = inspect_path_meta(&p) else {
                continue;
            };
            if meta.is_symlink_or_reparse || meta.is_cloud_placeholder {
                continue;
            }
            newest = newest.max(meta.mtime_secs);
            if meta.is_dir {
                stack.push((p, depth + 1));
            }
        }
    }
    newest
}

fn scan_ollama_models(
    rf: &RuleFile,
    rule: &RuleDef,
    options: &ScanOptions,
    _dedup: &HardlinkDeduplicator,
    locked_by: Option<String>,
) -> Vec<ScanHit> {
    let Some(home) = resolve_home_dir() else {
        return Vec::new();
    };
    let models_dir = home.join(".ollama").join("models");
    let summaries = crate::rules::ollama_gc::analyze_ollama_models(&models_dir);

    summaries
        .into_iter()
        .filter(|s| !crate::config::is_path_ignored(&s.manifest_path, &options.ignore_paths))
        .map(|s| {
            let shared_note_en = if s.shared_blob_count > 0 {
                format!(
                    "{} (Reclaimable exclusive blobs: {}, preserving {} shared base layer(s))",
                    rule.impact_note,
                    s.exclusive_blob_paths.len(),
                    s.shared_blob_count
                )
            } else {
                rule.impact_note.clone()
            };
            let shared_note_zh = if s.shared_blob_count > 0 {
                format!(
                    "{}（可回收独占权重层 {} 个，自动保留与其他模型共享的 {} 个基础层）",
                    rule.impact_note_zh,
                    s.exclusive_blob_paths.len(),
                    s.shared_blob_count
                )
            } else {
                rule.impact_note_zh.clone()
            };

            ScanHit {
                id: format!("{}::{}", rule.id, s.manifest_path.display()),
                rule_id: rule.id.clone(),
                category: rf.category.clone(),
                app_name: rf.app_name.clone(),
                app_name_zh: rf.app_name_zh.clone(),
                title: format!("Ollama Model: {}", s.model_name),
                title_zh: format!("Ollama 本地模型：{}", s.model_name),
                risk: rule.risk,
                default_checked: rule.default_checked,
                delete_mode: rule.delete_mode,
                requires_elevation: false,
                path: s.manifest_path,
                allocated_bytes: s.exclusive_bytes,
                file_count: (s.exclusive_blob_paths.len() + 1) as u64,
                last_modified_ts: s.mtime_secs,
                impact_note: shared_note_en,
                impact_note_zh: shared_note_zh,
                locked_by_process: locked_by.clone(),
                native_command: None,
            }
        })
        .collect()
}

fn scan_huggingface_hub(
    rf: &RuleFile,
    rule: &RuleDef,
    options: &ScanOptions,
    dedup: &HardlinkDeduplicator,
    locked_by: Option<String>,
) -> Vec<ScanHit> {
    let Some(home) = resolve_home_dir() else {
        return Vec::new();
    };
    let hub_dir = home.join(".cache").join("huggingface").join("hub");
    let Ok(entries) = fs::read_dir(hub_dir) else {
        return Vec::new();
    };

    let mut hits = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !(name.starts_with("models--") || name.starts_with("datasets--")) {
            continue;
        }
        let p = entry.path();
        if crate::config::is_path_ignored(&p, &options.ignore_paths)
            || crate::config::dir_contains_ignored(&p, &options.ignore_paths)
            || ProtectedBlocklist::check_path(&p).is_err()
        {
            continue;
        }
        let Ok(meta) = inspect_path_meta(&p) else {
            continue;
        };
        if !meta.is_dir || meta.is_symlink_or_reparse {
            continue;
        }
        let (bytes, files) = measure_dir_physical(&p, dedup);
        if bytes == 0 {
            continue;
        }
        let display_repo = name
            .trim_start_matches("models--")
            .trim_start_matches("datasets--")
            .replace("--", "/");
        hits.push(ScanHit {
            id: format!("{}::{}", rule.id, p.display()),
            rule_id: rule.id.clone(),
            category: rf.category.clone(),
            app_name: rf.app_name.clone(),
            app_name_zh: rf.app_name_zh.clone(),
            title: format!("HuggingFace Cache: {display_repo}"),
            title_zh: format!("HuggingFace 缓存：{display_repo}"),
            risk: rule.risk,
            default_checked: rule.default_checked,
            delete_mode: rule.delete_mode,
            requires_elevation: false,
            path: p,
            allocated_bytes: bytes,
            file_count: files,
            last_modified_ts: meta.mtime_secs,
            impact_note: rule.impact_note.clone(),
            impact_note_zh: rule.impact_note_zh.clone(),
            locked_by_process: locked_by.clone(),
            native_command: None,
        });
    }
    hits
}

fn scan_docker_system_df(
    rf: &RuleFile,
    rule: &RuleDef,
    locked_by: Option<String>,
) -> Vec<ScanHit> {
    let Ok(output) = Command::new("docker")
        .args(["system", "df", "--format", "{{json .}}"])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut reclaimable_total = 0u64;
    for line in stdout.lines() {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
            let kind = val.get("Type").and_then(|v| v.as_str()).unwrap_or("");
            if matches!(kind, "Build Cache" | "Images") {
                if let Some(rec_str) = val.get("Reclaimable").and_then(|v| v.as_str()) {
                    reclaimable_total = reclaimable_total.saturating_add(parse_docker_size(rec_str));
                }
            }
        }
    }

    if reclaimable_total == 0 {
        return Vec::new();
    }

    vec![ScanHit {
        id: format!("{}::docker-prune", rule.id),
        rule_id: rule.id.clone(),
        category: rf.category.clone(),
        app_name: rf.app_name.clone(),
        app_name_zh: rf.app_name_zh.clone(),
        title: rule.title.clone(),
        title_zh: rule.title_zh.clone(),
        risk: rule.risk,
        default_checked: rule.default_checked,
        delete_mode: DeleteMode::NativeCommand,
        requires_elevation: false,
        path: PathBuf::from("docker://system/build-cache"),
        allocated_bytes: reclaimable_total,
        file_count: 1,
        last_modified_ts: 0,
        impact_note: rule.impact_note.clone(),
        impact_note_zh: rule.impact_note_zh.clone(),
        locked_by_process: locked_by,
        native_command: Some("docker builder prune -f && docker image prune -f".to_string()),
    }]
}

pub(crate) fn parse_docker_size(s: &str) -> u64 {
    let token = s.split_whitespace().next().unwrap_or("0B");
    let idx = token
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(token.len());
    let num: f64 = token[..idx].parse().unwrap_or(0.0);
    let unit = token[idx..].to_ascii_uppercase();
    let mul = match unit.as_str() {
        "B" => 1.0,
        "KB" => 1_000.0,
        "KIB" => 1_024.0,
        "MB" => 1_000_000.0,
        "MIB" => 1_048_576.0,
        "GB" => 1_000_000_000.0,
        "GIB" => 1_073_741_824.0,
        "TB" => 1_000_000_000_000.0,
        "TIB" => 1_099_511_627_776.0,
        _ => 1.0,
    };
    (num * mul) as u64
}

pub fn measure_dir_physical(dir: &Path, dedup: &HardlinkDeduplicator) -> (u64, u64) {
    let Ok(entries) = fs::read_dir(dir) else {
        return (0, 0);
    };
    let mut total_bytes = 0u64;
    let mut total_files = 0u64;
    for entry in entries.flatten() {
        let p = entry.path();
        let Ok(meta) = inspect_path_meta(&p) else {
            continue;
        };
        if meta.is_symlink_or_reparse || meta.is_cloud_placeholder {
            continue;
        }
        if meta.is_dir {
            let (b, f) = measure_dir_physical(&p, dedup);
            total_bytes = total_bytes.saturating_add(b);
            total_files = total_files.saturating_add(f);
        } else if dedup.should_count(meta.dev, meta.ino, meta.nlink) {
            total_bytes = total_bytes.saturating_add(meta.allocated_bytes);
            total_files += 1;
        }
    }
    (total_bytes, total_files)
}
