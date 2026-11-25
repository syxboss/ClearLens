use crate::audit::append_audit_record;
use crate::models::AuditRecord;
use crate::platform::{inspect_path_meta, move_to_os_trash};
use crate::safety::ProtectedBlocklist;
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct OllamaModelSummary {
    pub manifest_path: PathBuf,
    pub model_name: String,
    pub total_bytes: u64,
    pub exclusive_bytes: u64,
    pub exclusive_blob_paths: Vec<PathBuf>,
    pub shared_blob_count: usize,
    pub mtime_secs: i64,
}

#[derive(Debug, Clone)]
pub struct OllamaCleanOutcome {
    pub freed_bytes: u64,
    pub reclaimed_blobs: usize,
    pub preserved_shared_blobs: usize,
}

/// Parses all manifests under `<home>/.ollama/models/manifests` and computes
/// reference counts for every referenced blob digest (`config.digest` + `layers[*].digest`).
pub fn analyze_ollama_models(models_dir: &Path) -> Vec<OllamaModelSummary> {
    let manifests_dir = models_dir.join("manifests");
    let blobs_dir = models_dir.join("blobs");
    if !manifests_dir.is_dir() {
        return Vec::new();
    }

    let mut manifest_files = Vec::new();
    collect_files(&manifests_dir, &mut manifest_files);
    manifest_files.sort();

    // Pass 1: parse digests per manifest and build global blob reference counts
    let mut parsed: Vec<(PathBuf, Vec<String>)> = Vec::with_capacity(manifest_files.len());
    let mut ref_counts: HashMap<String, usize> = HashMap::new();

    for mpath in manifest_files {
        let Ok(raw) = fs::read_to_string(&mpath) else {
            continue;
        };
        let digests = extract_manifest_digests(&raw);
        if digests.is_empty() {
            continue;
        }
        // Deduplicate digests within a single manifest before incrementing global ref_count
        let unique: HashSet<String> = digests.into_iter().collect();
        for d in &unique {
            *ref_counts.entry(d.clone()).or_insert(0) += 1;
        }
        let mut sorted: Vec<String> = unique.into_iter().collect();
        sorted.sort();
        parsed.push((mpath, sorted));
    }

    // Pass 2: compute total vs exclusively-reclaimable bytes for each model
    let mut summaries = Vec::new();
    for (mpath, digests) in parsed {
        let mut total_bytes = inspect_path_meta(&mpath)
            .map(|m| m.allocated_bytes)
            .unwrap_or(0);
        let mut exclusive_bytes = total_bytes;
        let mut exclusive_blob_paths = Vec::new();
        let mut shared_blob_count = 0usize;

        for digest in &digests {
            let Some(blob_file_name) = safe_blob_filename(digest) else {
                continue;
            };
            let blob_path = blobs_dir.join(&blob_file_name);
            if blob_path.parent() != Some(blobs_dir.as_path()) {
                continue;
            }
            let Ok(meta) = inspect_path_meta(&blob_path) else {
                continue;
            };
            if meta.is_symlink_or_reparse || meta.is_cloud_placeholder {
                continue;
            }
            total_bytes = total_bytes.saturating_add(meta.allocated_bytes);
            if ref_counts.get(digest).copied().unwrap_or(0) == 1 {
                exclusive_bytes = exclusive_bytes.saturating_add(meta.allocated_bytes);
                exclusive_blob_paths.push(blob_path);
            } else {
                shared_blob_count += 1;
            }
        }

        if total_bytes == 0 {
            continue;
        }

        let model_name = mpath
            .strip_prefix(&manifests_dir)
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|_| mpath.display().to_string());
        let mtime_secs = inspect_path_meta(&mpath).map(|m| m.mtime_secs).unwrap_or(0);

        summaries.push(OllamaModelSummary {
            manifest_path: mpath,
            model_name,
            total_bytes,
            exclusive_bytes,
            exclusive_blob_paths,
            shared_blob_count,
            mtime_secs,
        });
    }

    summaries
}

/// Safely cleans an Ollama model manifest AND all exclusively-referenced (ref_count == 1) blobs
/// by routing them to OS Trash while preserving every blob shared with other remaining models.
pub fn clean_ollama_model(manifest_path: &Path, dry_run: bool) -> Result<OllamaCleanOutcome, String> {
    ProtectedBlocklist::check_path(manifest_path).map_err(|e| e.to_string())?;
    let ignore_paths = crate::config::load_app_config().ignore_paths;
    if crate::config::is_path_ignored(manifest_path, &ignore_paths) {
        return Err("skipped: manifest path is protected by ignore whitelist".to_string());
    }
    let mmeta = inspect_path_meta(manifest_path)
        .map_err(|_| format!("Ollama manifest not found: {}", manifest_path.display()))?;
    if mmeta.is_dir || mmeta.is_symlink_or_reparse || mmeta.is_cloud_placeholder {
        return Err(format!(
            "refusing non-regular Ollama manifest target: {}",
            manifest_path.display()
        ));
    }

    let models_dir = find_ollama_models_root(manifest_path)
        .filter(|dir| is_valid_ollama_models_root(dir))
        .ok_or_else(|| {
            format!(
                "refusing Ollama GC: {} is not inside a valid Ollama models directory",
                manifest_path.display()
            )
        })?;

    let summaries = analyze_ollama_models(&models_dir);
    let summary = summaries
        .into_iter()
        .find(|s| crate::config::paths_equal_for_policy(&s.manifest_path, manifest_path))
        .ok_or_else(|| format!("Ollama manifest not found or empty: {}", manifest_path.display()))?;

    let blobs_dir = models_dir.join("blobs");
    let eligible_blobs: Vec<PathBuf> = summary
        .exclusive_blob_paths
        .iter()
        .filter(|blob_path| {
            blob_path.parent() == Some(blobs_dir.as_path())
                && ProtectedBlocklist::check_path(blob_path).is_ok()
                && !crate::config::is_path_ignored(blob_path, &ignore_paths)
        })
        .cloned()
        .collect();

    if dry_run {
        return Ok(OllamaCleanOutcome {
            freed_bytes: summary.exclusive_bytes,
            reclaimed_blobs: eligible_blobs.len(),
            preserved_shared_blobs: summary.shared_blob_count,
        });
    }

    // Move manifest first, then each exclusive blob strictly inside `<models>/blobs/` to OS Trash
    let manifest_bytes = mmeta.allocated_bytes;
    move_to_os_trash(&summary.manifest_path)?;
    let mut reclaimed_blobs = 0usize;
    let mut reclaimed_bytes = manifest_bytes;
    for blob_path in &eligible_blobs {
        if let Ok(bmeta) = inspect_path_meta(blob_path) {
            if !bmeta.is_dir && !bmeta.is_symlink_or_reparse && !bmeta.is_cloud_placeholder {
                move_to_os_trash(blob_path)?;
                reclaimed_blobs += 1;
                reclaimed_bytes = reclaimed_bytes.saturating_add(bmeta.allocated_bytes);
            }
        }
    }

    let note = format!(
        "reclaimed {} exclusive blobs, preserved {} shared blobs",
        reclaimed_blobs, summary.shared_blob_count
    );
    let _ = append_audit_record(&AuditRecord {
        timestamp: Utc::now().to_rfc3339(),
        rule_id: "ai.ollama_models".to_string(),
        path: manifest_path.to_path_buf(),
        bytes_freed: reclaimed_bytes,
        method: "trash".to_string(),
        success: true,
        note: Some(note),
    });

    Ok(OllamaCleanOutcome {
        freed_bytes: reclaimed_bytes,
        reclaimed_blobs,
        preserved_shared_blobs: summary.shared_blob_count,
    })
}

fn is_valid_ollama_models_root(models_dir: &Path) -> bool {
    if !models_dir.join("manifests").is_dir() || !models_dir.join("blobs").is_dir() {
        return false;
    }
    let norm = models_dir
        .to_string_lossy()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase();
    if norm.ends_with("/.ollama/models") {
        return true;
    }
    if let Some(env_models) = std::env::var_os("OLLAMA_MODELS").filter(|v| !v.is_empty()) {
        return crate::config::paths_equal_for_policy(models_dir, Path::new(&env_models));
    }
    false
}

fn find_ollama_models_root(manifest_path: &Path) -> Option<PathBuf> {
    let mut cur = manifest_path.parent()?;
    loop {
        if cur.file_name().and_then(|n| n.to_str()) == Some("manifests") {
            return cur.parent().map(|p| p.to_path_buf());
        }
        cur = cur.parent()?;
    }
}

/// Validates an OCI digest string (`<algo>:<alnum_hash>`) so malformed or malicious manifests
/// can NEVER traverse outside `<models>/blobs` via `..`, `/`, or `\`.
fn is_valid_oci_digest(d: &str) -> bool {
    let Some((algo, hash)) = d.split_once(':') else {
        return false;
    };
    !algo.is_empty()
        && algo.len() <= 16
        && algo.chars().all(|c| c.is_ascii_alphanumeric())
        && !hash.is_empty()
        && hash.len() <= 128
        && hash.chars().all(|c| c.is_ascii_alphanumeric())
}

fn safe_blob_filename(digest: &str) -> Option<String> {
    if !is_valid_oci_digest(digest) {
        return None;
    }
    let (algo, hash) = digest.split_once(':')?;
    Some(format!("{algo}-{hash}"))
}

fn extract_manifest_digests(raw: &str) -> Vec<String> {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(raw) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(cfg_digest) = val
        .get("config")
        .and_then(|c| c.get("digest"))
        .and_then(|d| d.as_str())
    {
        if is_valid_oci_digest(cfg_digest) {
            out.push(cfg_digest.to_string());
        }
    }
    if let Some(layers) = val.get("layers").and_then(|l| l.as_array()) {
        for layer in layers {
            if let Some(d) = layer.get("digest").and_then(|x| x.as_str()) {
                if is_valid_oci_digest(d) {
                    out.push(d.to_string());
                }
            }
        }
    }
    out
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        let Ok(meta) = inspect_path_meta(&p) else {
            continue;
        };
        if meta.is_symlink_or_reparse || meta.is_cloud_placeholder {
            continue;
        }
        if meta.is_dir {
            collect_files(&p, out);
        } else {
            out.push(p);
        }
    }
}
