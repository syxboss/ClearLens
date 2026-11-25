use crate::config::{dir_contains_ignored, is_path_ignored};
use crate::models::{RuleDef, RuleFile, ScanHit, ScanOptions, ScanProgressEvent};
use crate::platform::inspect_path_meta;
use crate::rules::expand_env_vars;
use crate::safety::{HardlinkDeduplicator, ProtectedBlocklist};
use globset::{Glob, GlobSet, GlobSetBuilder};
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn evaluate_glob_rule<F>(
    rf: &RuleFile,
    rule: &RuleDef,
    options: &ScanOptions,
    dedup: &HardlinkDeduplicator,
    locked_by: Option<String>,
    skipped_warnings: &mut usize,
    on_progress: &mut F,
) -> Vec<ScanHit>
where
    F: FnMut(ScanProgressEvent),
{
    let raw_patterns = rule.paths.for_platform(options.platform);
    if raw_patterns.is_empty() {
        return Vec::new();
    }

    let exclude_set = build_exclude_set(&rule.exclude.patterns);
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let cutoff_secs = now_secs - (rule.min_age_days as i64) * 86_400;

    let mut targets: Vec<(PathBuf, bool, Option<Glob>)> = Vec::new();
    for raw in raw_patterns {
        let Some(expanded) = expand_env_vars(raw, options.platform) else {
            continue;
        };
        let resolved = resolve_pattern_roots(&expanded);
        for (target_path, file_glob) in resolved {
            if !targets.iter().any(|(p, _, _)| p == &target_path) {
                targets.push((target_path, rule.min_age_days > 0, file_glob));
            }
        }
    }

    let mut hits = Vec::new();
    for (target_path, check_age, file_glob) in targets {
        if is_path_ignored(&target_path, &options.ignore_paths) {
            continue;
        }
        if ProtectedBlocklist::check_path(&target_path).is_err() {
            *skipped_warnings += 1;
            on_progress(ScanProgressEvent::WarningSkipped {
                path: target_path.display().to_string(),
                reason: "protected_blocklist".to_string(),
            });
            continue;
        }

        let Ok(meta) = inspect_path_meta(&target_path) else {
            continue;
        };
        if meta.is_symlink_or_reparse || meta.is_cloud_placeholder {
            *skipped_warnings += 1;
            continue;
        }

        if meta.is_dir {
            let stats = measure_cleanable_dir(
                &target_path,
                &exclude_set,
                &options.ignore_paths,
                file_glob.as_ref(),
                if check_age { Some(cutoff_secs) } else { None },
                dedup,
            );
            if stats.file_count > 0 && stats.allocated_bytes > 0 {
                // Emit individual eligible entries whenever age/exclude filters or inner ignored subdirs exist
                let has_inner_ignore = dir_contains_ignored(&target_path, &options.ignore_paths);
                if (stats.partial_filtered || has_inner_ignore) && !stats.eligible_items.is_empty() {
                    for item in stats.eligible_items {
                        hits.push(build_hit(rf, rule, item.path, item.bytes, item.files, item.mtime, &locked_by));
                    }
                } else {
                    hits.push(build_hit(
                        rf,
                        rule,
                        target_path,
                        stats.allocated_bytes,
                        stats.file_count,
                        stats.newest_mtime,
                        &locked_by,
                    ));
                }
            }
        } else {
            // Single file match (e.g., ~/Downloads/*.dmg or thumbcache_*.db)
            if check_age && meta.mtime_secs > cutoff_secs {
                continue;
            }
            if is_excluded(&exclude_set, &target_path) {
                continue;
            }
            if !dedup.should_count(meta.dev, meta.ino, meta.nlink) {
                continue;
            }
            if meta.allocated_bytes > 0 {
                hits.push(build_hit(
                    rf,
                    rule,
                    target_path,
                    meta.allocated_bytes,
                    1,
                    meta.mtime_secs,
                    &locked_by,
                ));
            }
        }
    }

    hits
}

fn build_hit(
    rf: &RuleFile,
    rule: &RuleDef,
    path: PathBuf,
    allocated_bytes: u64,
    file_count: u64,
    last_modified_ts: i64,
    locked_by: &Option<String>,
) -> ScanHit {
    ScanHit {
        id: format!("{}::{}", rule.id, path.display()),
        rule_id: rule.id.clone(),
        category: rf.category.clone(),
        app_name: rf.app_name.clone(),
        app_name_zh: if rf.app_name_zh.is_empty() {
            rf.app_name.clone()
        } else {
            rf.app_name_zh.clone()
        },
        title: rule.title.clone(),
        title_zh: if rule.title_zh.is_empty() {
            rule.title.clone()
        } else {
            rule.title_zh.clone()
        },
        risk: rule.risk,
        default_checked: rule.default_checked,
        delete_mode: rule.delete_mode,
        requires_elevation: rule.requires_elevation,
        path,
        allocated_bytes,
        file_count,
        last_modified_ts,
        impact_note: rule.impact_note.clone(),
        impact_note_zh: if rule.impact_note_zh.is_empty() {
            rule.impact_note.clone()
        } else {
            rule.impact_note_zh.clone()
        },
        locked_by_process: locked_by.clone(),
        native_command: None,
    }
}

pub(crate) fn build_exclude_set(patterns: &[String]) -> Option<GlobSet> {
    if patterns.is_empty() {
        return None;
    }
    let mut builder = GlobSetBuilder::new();
    for p in patterns {
        if let Ok(g) = globset::GlobBuilder::new(&p.replace('\\', "/"))
            .case_insensitive(true)
            .build()
        {
            builder.add(g);
        }
    }
    builder.build().ok()
}

pub(crate) fn is_excluded(exclude_set: &Option<GlobSet>, path: &Path) -> bool {
    let Some(gs) = exclude_set else {
        return false;
    };
    let s = path.to_string_lossy().replace('\\', "/");
    gs.is_match(&s)
}

pub(crate) fn resolve_anchor_dirs(pattern: &str) -> Vec<PathBuf> {
    let norm = pattern.replace('\\', "/");
    if !norm.ends_with("/**") {
        return Vec::new();
    }
    resolve_pattern_roots(&norm)
        .into_iter()
        .map(|(p, _)| p)
        .collect()
}

/// Expands wildcards segment-by-segment up to `/**` or a trailing file glob like `*.dmg`.
fn resolve_pattern_roots(pattern: &str) -> Vec<(PathBuf, Option<Glob>)> {
    let norm = pattern.replace('\\', "/");
    let has_recursive_suffix = norm.ends_with("/**");
    let base_pat = norm.strip_suffix("/**").unwrap_or(&norm);

    // Check if the final segment is a file pattern like `*.dmg` or `thumbcache_*.db`
    let segments: Vec<&str> = base_pat.split('/').collect();
    if segments.is_empty() {
        return Vec::new();
    }

    let leading_slash = base_pat.starts_with('/');
    let mut current_paths: Vec<PathBuf> = if leading_slash {
        vec![PathBuf::from("/")]
    } else if segments[0].ends_with(':') {
        vec![PathBuf::from(format!("{}/", segments[0]))]
    } else {
        vec![PathBuf::from(".")]
    };

    let start_idx = if leading_slash || segments[0].ends_with(':') {
        1
    } else {
        0
    };

    for (idx, seg) in segments.iter().enumerate().skip(start_idx) {
        if seg.is_empty() {
            continue;
        }
        let is_last = idx == segments.len() - 1;
        if *seg == "**" {
            // Recursive wildcard mid-path: expand directories up to depth 3
            let mut next = Vec::new();
            for p in &current_paths {
                collect_subdirs_bounded(p, 3, &mut next);
            }
            current_paths = next;
            continue;
        }

        if seg.contains('*') || seg.contains('?') {
            let Ok(glob) = Glob::new(seg) else {
                return Vec::new();
            };
            let matcher = glob.compile_matcher();
            let mut next = Vec::new();
            for dir in &current_paths {
                let Ok(entries) = fs::read_dir(dir) else {
                    continue;
                };
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if matcher.is_match(name_str.as_ref()) {
                        let p = entry.path();
                        // Never follow symlinks when expanding globs
                        if inspect_path_meta(&p)
                            .map(|m| !m.is_symlink_or_reparse)
                            .unwrap_or(false)
                        {
                            if is_last && !has_recursive_suffix {
                                next.push(p);
                            } else if p.is_dir() {
                                next.push(p);
                            }
                        }
                    }
                }
            }
            current_paths = next;
        } else {
            current_paths = current_paths
                .into_iter()
                .map(|p| p.join(seg))
                .filter(|p| p.exists())
                .collect();
        }
    }

    current_paths
        .into_iter()
        .map(|p| (p, None))
        .collect()
}

fn collect_subdirs_bounded(dir: &Path, max_depth: usize, out: &mut Vec<PathBuf>) {
    out.push(dir.to_path_buf());
    if max_depth == 0 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if let Ok(meta) = inspect_path_meta(&p) {
            if meta.is_dir && !meta.is_symlink_or_reparse {
                collect_subdirs_bounded(&p, max_depth - 1, out);
            }
        }
    }
}

struct DirMeasure {
    allocated_bytes: u64,
    file_count: u64,
    newest_mtime: i64,
    partial_filtered: bool,
    eligible_items: Vec<EligibleFile>,
}

struct EligibleFile {
    path: PathBuf,
    bytes: u64,
    files: u64,
    mtime: i64,
}

fn measure_cleanable_dir(
    dir: &Path,
    exclude_set: &Option<GlobSet>,
    ignore_paths: &[PathBuf],
    _file_glob: Option<&Glob>,
    cutoff_secs: Option<i64>,
    dedup: &HardlinkDeduplicator,
) -> DirMeasure {
    let entries: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(rd) => rd.flatten().map(|e| e.path()).collect(),
        Err(_) => {
            return DirMeasure {
                allocated_bytes: 0,
                file_count: 0,
                newest_mtime: 0,
                partial_filtered: false,
                eligible_items: Vec::new(),
            };
        }
    };

    let sub_results: Vec<(u64, u64, i64, bool, Vec<EligibleFile>)> = entries
        .par_iter()
        .map(|p| walk_single_entry(p, exclude_set, ignore_paths, cutoff_secs, dedup))
        .collect();

    let mut total_bytes = 0u64;
    let mut total_files = 0u64;
    let mut newest_mtime = 0i64;
    let mut partial_filtered = false;
    let mut eligible_items = Vec::new();

    for (b, f, m, skipped_any, mut items) in sub_results {
        total_bytes = total_bytes.saturating_add(b);
        total_files = total_files.saturating_add(f);
        newest_mtime = newest_mtime.max(m);
        partial_filtered |= skipped_any;
        eligible_items.append(&mut items);
    }

    DirMeasure {
        allocated_bytes: total_bytes,
        file_count: total_files,
        newest_mtime,
        partial_filtered,
        eligible_items,
    }
}

fn walk_single_entry(
    path: &Path,
    exclude_set: &Option<GlobSet>,
    ignore_paths: &[PathBuf],
    cutoff_secs: Option<i64>,
    dedup: &HardlinkDeduplicator,
) -> (u64, u64, i64, bool, Vec<EligibleFile>) {
    if is_excluded(exclude_set, path)
        || is_path_ignored(path, ignore_paths)
        || ProtectedBlocklist::check_path(path).is_err()
    {
        return (0, 0, 0, true, Vec::new());
    }
    let Ok(meta) = inspect_path_meta(path) else {
        return (0, 0, 0, false, Vec::new());
    };
    if meta.is_symlink_or_reparse || meta.is_cloud_placeholder {
        return (0, 0, 0, true, Vec::new());
    }
    if meta.is_dir {
        let m = measure_cleanable_dir(path, exclude_set, ignore_paths, None, cutoff_secs, dedup);
        let has_inner_ignore = dir_contains_ignored(path, ignore_paths);
        if !m.partial_filtered && !has_inner_ignore && m.file_count > 0 {
            let item = EligibleFile {
                path: path.to_path_buf(),
                bytes: m.allocated_bytes,
                files: m.file_count,
                mtime: m.newest_mtime,
            };
            return (m.allocated_bytes, m.file_count, m.newest_mtime, false, vec![item]);
        }
        return (
            m.allocated_bytes,
            m.file_count,
            m.newest_mtime,
            m.partial_filtered || has_inner_ignore,
            m.eligible_items,
        );
    }

    if let Some(cutoff) = cutoff_secs {
        if meta.mtime_secs > cutoff {
            return (0, 0, 0, true, Vec::new());
        }
    }
    if !dedup.should_count(meta.dev, meta.ino, meta.nlink) {
        return (0, 0, 0, false, Vec::new());
    }
    if meta.allocated_bytes == 0 {
        return (0, 0, 0, false, Vec::new());
    }
    let item = EligibleFile {
        path: path.to_path_buf(),
        bytes: meta.allocated_bytes,
        files: 1,
        mtime: meta.mtime_secs,
    };
    (meta.allocated_bytes, 1, meta.mtime_secs, false, vec![item])
}
