pub mod glob_engine;
pub mod ollama_gc;
pub mod smart_scanners;

use crate::models::{
    CategorySummary, DeleteMode, RiskLevel, RiskSummary, RuleFile, RuleKind, ScanHit, ScanOptions,
    ScanProgressEvent, ScanReport, TargetPlatform,
};
use crate::platform::resolve_home_dir;
use crate::safety::{
    is_metadata_reparse_or_symlink, validate_rule_file_patterns, HardlinkDeduplicator,
    ProcessMonitor, ProtectedBlocklist, SafetyError,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

const EMBEDDED_RULES: &[(&str, &str)] = &[
    ("system/os_junk.toml", include_str!("../../../../rules/system/os_junk.toml")),
    ("browsers/browsers.toml", include_str!("../../../../rules/browsers/browsers.toml")),
    ("dev_ai/toolchains_and_ai.toml", include_str!("../../../../rules/dev_ai/toolchains_and_ai.toml")),
    ("social_office/im_apps.toml", include_str!("../../../../rules/social_office/im_apps.toml")),
    ("creative_media/creative.toml", include_str!("../../../../rules/creative_media/creative.toml")),
    ("gaming/gaming_shaders.toml", include_str!("../../../../rules/gaming/gaming_shaders.toml")),
];

pub fn validate_toml_str(raw: &str) -> Result<RuleFile, String> {
    let rf: RuleFile = toml::from_str(raw).map_err(|e| format!("TOML parse error: {e}"))?;
    validate_rule_file(&rf).map_err(|e| e.to_string())?;
    Ok(rf)
}

pub fn validate_rule_file(rf: &RuleFile) -> Result<(), SafetyError> {
    validate_rule_file_patterns(rf)
}

pub fn load_embedded_rules() -> Result<Vec<RuleFile>, String> {
    let mut files = Vec::new();
    for (name, raw) in EMBEDDED_RULES {
        let rf = validate_toml_str(raw).map_err(|e| format!("embedded rule {name}: {e}"))?;
        files.push(rf);
    }
    Ok(files)
}

pub fn load_all_rules() -> Result<Vec<RuleFile>, String> {
    let mut files = load_embedded_rules()?;

    // Also load any custom declarative glob rules dropped in ~/.clearlens/rules/*.toml
    // Security: reject symlinks and forbid SmartScanner, NativeCommand, or elevation flags in custom TOML.
    if let Some(home) = resolve_home_dir() {
        let custom_dir = home.join(".clearlens").join("rules");
        if let Ok(entries) = fs::read_dir(custom_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()) == Some("toml") {
                    if let Ok(meta) = fs::symlink_metadata(&p) {
                        if is_metadata_reparse_or_symlink(&meta) || !meta.is_file() {
                            continue;
                        }
                    }
                    if let Ok(raw) = fs::read_to_string(&p) {
                        if let Ok(mut rf) = validate_toml_str(&raw) {
                            rf.rules.retain(|r| {
                                r.kind == RuleKind::Glob && r.delete_mode != DeleteMode::NativeCommand
                            });
                            for r in &mut rf.rules {
                                r.requires_elevation = false;
                            }
                            if !rf.rules.is_empty() {
                                files.push(rf);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(files)
}

pub fn run_rule_scan<F>(
    options: &ScanOptions,
    cancel: &AtomicBool,
    mut on_progress: F,
) -> Result<ScanReport, String>
where
    F: FnMut(ScanProgressEvent),
{
    let start = Instant::now();
    let rule_files = load_all_rules()?;
    let proc_monitor = ProcessMonitor::snapshot();
    let dedup = HardlinkDeduplicator::default();
    let mut hits: Vec<ScanHit> = Vec::new();
    let mut skipped_warnings: usize = 0;

    for rf in &rule_files {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        if let Some(filter) = &options.categories {
            if !filter.iter().any(|c| c == &rf.category) {
                continue;
            }
        }

        let proc_candidates = match options.platform {
            TargetPlatform::MacOs => &rf.process_names_mac,
            TargetPlatform::Windows => &rf.process_names_win,
            TargetPlatform::Linux => &rf.process_names_mac,
        };
        let locked_by = proc_monitor.find_running(proc_candidates);

        for rule in &rf.rules {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            let rule_hits = match rule.kind {
                RuleKind::Glob => glob_engine::evaluate_glob_rule(
                    rf,
                    rule,
                    options,
                    &dedup,
                    locked_by.clone(),
                    &mut skipped_warnings,
                    &mut on_progress,
                ),
                RuleKind::SmartScanner => smart_scanners::evaluate_smart_rule(
                    rf,
                    rule,
                    options,
                    &dedup,
                    locked_by.clone(),
                    cancel,
                ),
            };

            for h in rule_hits {
                if crate::config::is_path_ignored(&h.path, &options.ignore_paths) {
                    continue;
                }
                if ProtectedBlocklist::check_path(&h.path).is_err() {
                    skipped_warnings += 1;
                    continue;
                }
                on_progress(ScanProgressEvent::RuleMatched {
                    rule_id: h.rule_id.clone(),
                    added_bytes: h.allocated_bytes,
                    added_files: h.file_count,
                });
                hits.push(h);
            }
        }
    }

    if cancel.load(Ordering::Relaxed) {
        return Err("scan cancelled".to_string());
    }

    hits.sort_by(|a, b| b.allocated_bytes.cmp(&a.allocated_bytes));

    let mut total_reclaimable_bytes = 0u64;
    let mut total_files = 0u64;
    let mut safe_bytes = 0u64;
    let mut recreatable_bytes = 0u64;
    let mut review_required_bytes = 0u64;
    let mut cat_map: BTreeMap<String, (u64, u64, usize)> = BTreeMap::new();

    for h in &hits {
        total_reclaimable_bytes = total_reclaimable_bytes.saturating_add(h.allocated_bytes);
        total_files = total_files.saturating_add(h.file_count);
        match h.risk {
            RiskLevel::Safe => safe_bytes += h.allocated_bytes,
            RiskLevel::Recreatable => recreatable_bytes += h.allocated_bytes,
            RiskLevel::ReviewRequired => review_required_bytes += h.allocated_bytes,
        }
        let entry = cat_map.entry(h.category.clone()).or_insert((0, 0, 0));
        entry.0 += h.allocated_bytes;
        entry.1 += h.file_count;
        entry.2 += 1;
    }

    let categories = cat_map
        .into_iter()
        .map(|(category, (total_bytes, file_count, hit_count))| CategorySummary {
            category,
            total_bytes,
            file_count,
            hit_count,
        })
        .collect();

    let duration_ms = start.elapsed().as_millis() as u64;
    on_progress(ScanProgressEvent::Completed {
        duration_ms,
        total_reclaimable_bytes,
        hit_count: hits.len(),
    });

    Ok(ScanReport {
        platform: options.platform,
        duration_ms,
        total_reclaimable_bytes,
        total_files,
        skipped_warnings,
        risk_summary: RiskSummary {
            safe_bytes,
            recreatable_bytes,
            review_required_bytes,
        },
        categories,
        hits,
    })
}

pub fn expand_env_vars(pattern: &str, platform: TargetPlatform) -> Option<String> {
    let home = resolve_home_dir()?;
    let home_str = home.to_string_lossy().replace('\\', "/");

    let mut s = pattern.replace('\\', "/");
    if s == "~" {
        s = home_str.clone();
    } else if let Some(rest) = s.strip_prefix("~/") {
        s = format!("{}/{rest}", home_str.trim_end_matches('/'));
    } else if s.contains("$HOME") {
        s = s.replace("$HOME", home_str.trim_end_matches('/'));
    }

    let vars = [
        ("%USERPROFILE%", "USERPROFILE", home_str.clone()),
        (
            "%LOCALAPPDATA%",
            "LOCALAPPDATA",
            match platform {
                TargetPlatform::Windows => format!("{}/AppData/Local", home_str.trim_end_matches('/')),
                _ => format!("{}/.local/share", home_str.trim_end_matches('/')),
            },
        ),
        (
            "%APPDATA%",
            "APPDATA",
            match platform {
                TargetPlatform::Windows => format!("{}/AppData/Roaming", home_str.trim_end_matches('/')),
                _ => format!("{}/.config", home_str.trim_end_matches('/')),
            },
        ),
        ("%TEMP%", "TEMP", std::env::temp_dir().to_string_lossy().to_string()),
        ("%WINDIR%", "WINDIR", "C:/Windows".to_string()),
        (
            "%PROGRAMFILES(X86)%",
            "PROGRAMFILES(X86)",
            "C:/Program Files (x86)".to_string(),
        ),
    ];

    for (token, env_key, default_val) in vars {
        if s.contains(token) {
            let val = std::env::var(env_key)
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or(default_val)
                .replace('\\', "/");
            s = s.replace(token, val.trim_end_matches('/'));
        }
    }

    Some(PathBuf::from(s).to_string_lossy().to_string())
}

pub(crate) struct RuleCleanPolicy {
    pub risk: RiskLevel,
    pub delete_mode: DeleteMode,
    pub min_age_days: u32,
    pub requires_elevation: bool,
    pub exclude_set: Option<globset::GlobSet>,
    pub anchor_dirs: Vec<PathBuf>,
}

fn collect_rule_anchor_dirs(
    rule: &crate::models::RuleDef,
    platforms: &[TargetPlatform],
    include_static_nonexistent: bool,
) -> Vec<PathBuf> {
    let mut anchor_dirs = Vec::new();
    if rule.kind != RuleKind::Glob {
        return anchor_dirs;
    }
    for &plat in platforms {
        for raw in rule.paths.for_platform(plat) {
            let raw_norm = raw.replace('\\', "/");
            if raw_norm.ends_with("/**") {
                if let Some(exp) = expand_env_vars(raw, plat) {
                    if include_static_nonexistent {
                        let exp_norm = exp.replace('\\', "/");
                        if let Some(base) = exp_norm.strip_suffix("/**") {
                            if !base.contains('*') && !base.contains('?') {
                                let static_p = PathBuf::from(base);
                                if !anchor_dirs.contains(&static_p) {
                                    anchor_dirs.push(static_p);
                                }
                            }
                        }
                    }
                    for p in glob_engine::resolve_anchor_dirs(&exp) {
                        if !anchor_dirs.contains(&p) {
                            anchor_dirs.push(p);
                        }
                    }
                }
            }
        }
    }
    anchor_dirs
}

pub(crate) fn build_clean_policies() -> std::collections::HashMap<String, RuleCleanPolicy> {
    let mut map = std::collections::HashMap::new();
    let Ok(files) = load_all_rules() else {
        return map;
    };
    let all_plats = [
        TargetPlatform::MacOs,
        TargetPlatform::Windows,
        TargetPlatform::Linux,
    ];
    for rf in files {
        for rule in rf.rules {
            let exclude_set = glob_engine::build_exclude_set(&rule.exclude.patterns);
            let anchor_dirs = collect_rule_anchor_dirs(&rule, &all_plats, false);
            map.insert(
                rule.id,
                RuleCleanPolicy {
                    risk: rule.risk,
                    delete_mode: rule.delete_mode,
                    min_age_days: rule.min_age_days,
                    requires_elevation: rule.requires_elevation,
                    exclude_set,
                    anchor_dirs,
                },
            );
        }
    }
    map
}

pub(crate) fn build_builtin_elevation_policies() -> std::collections::HashMap<String, RuleCleanPolicy> {
    let mut map = std::collections::HashMap::new();
    let Ok(files) = load_embedded_rules() else {
        return map;
    };
    let all_plats = [
        TargetPlatform::MacOs,
        TargetPlatform::Windows,
        TargetPlatform::Linux,
    ];
    for rf in files {
        for rule in rf.rules {
            if !rule.requires_elevation {
                continue;
            }
            let exclude_set = glob_engine::build_exclude_set(&rule.exclude.patterns);
            let anchor_dirs = collect_rule_anchor_dirs(&rule, &all_plats, true);
            map.insert(
                rule.id,
                RuleCleanPolicy {
                    risk: rule.risk,
                    delete_mode: rule.delete_mode,
                    min_age_days: rule.min_age_days,
                    requires_elevation: true,
                    exclude_set,
                    anchor_dirs,
                },
            );
        }
    }
    map
}
