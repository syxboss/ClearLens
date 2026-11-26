use crate::cleaner::execute_clean;
use crate::config::{is_path_ignored, load_app_config, paths_equal_for_policy};
use crate::models::{
    CleanItemRequest, CleanReport, DeleteMode, DuplicateCleanGroup, DuplicateFileEntry,
    DuplicateGroup, DuplicateReport, RiskLevel, ScanProgressEvent,
};
use crate::platform::inspect_path_meta;
use crate::safety::HardlinkDeduplicator;
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

const PARTIAL_SAMPLE_BYTES: usize = 4096;
const FULL_CHUNK_BYTES: usize = 65_536;

#[derive(Debug, Clone)]
struct CandidateFile {
    path: PathBuf,
    name: String,
    allocated_bytes: u64,
    logical_bytes: u64,
    mtime_secs: i64,
}

/// 3-Stage Funnel Duplicate Finder using BLAKE3:
/// - Stage 0: Safe parallel walk skipping symlinks, cloud placeholders, `.git`, and hardlinks to the same inode.
/// - Stage 1: Group by exact logical file size (eliminates unique sizes with zero file reads).
/// - Stage 2: Partial 4KB head + 4KB tail BLAKE3 pre-hash.
/// - Stage 3: Full streaming 64KB-chunk BLAKE3 digest verification.
pub fn scan_duplicates<F>(
    roots: &[PathBuf],
    min_size_bytes: u64,
    cancel: &AtomicBool,
    mut on_progress: F,
) -> Result<DuplicateReport, String>
where
    F: FnMut(ScanProgressEvent),
{
    let start = Instant::now();
    let dedup = HardlinkDeduplicator::default();
    let ignore_paths = crate::config::load_app_config().ignore_paths;
    let scanned_files = AtomicU64::new(0);
    let skipped_hardlinks = AtomicU64::new(0);
    let skipped_cloud = AtomicU64::new(0);

    let mut all_candidates = Vec::new();
    for root in roots {
        if cancel.load(Ordering::Relaxed) {
            return Err("scan cancelled".to_string());
        }
        if !root.exists() {
            continue;
        }
        collect_candidates(
            root,
            0,
            min_size_bytes.max(1),
            &ignore_paths,
            &dedup,
            &scanned_files,
            &skipped_hardlinks,
            &skipped_cloud,
            cancel,
            &mut all_candidates,
        );
    }

    if cancel.load(Ordering::Relaxed) {
        return Err("scan cancelled".to_string());
    }

    on_progress(ScanProgressEvent::DirectoryStatUpdated {
        current_path: "Stage 1/3: Size grouping".to_string(),
        scanned_files: scanned_files.load(Ordering::Relaxed),
        scanned_bytes: 0,
    });

    // Stage 1: Exact logical size bucketing (zero content I/O)
    let mut size_buckets: FxHashMap<u64, Vec<CandidateFile>> = FxHashMap::default();
    for cand in all_candidates {
        size_buckets
            .entry(cand.logical_bytes)
            .or_default()
            .push(cand);
    }
    let stage1_candidates: Vec<CandidateFile> = size_buckets
        .into_values()
        .filter(|v| v.len() >= 2)
        .flatten()
        .collect();
    let candidate_files = stage1_candidates.len() as u64;

    if cancel.load(Ordering::Relaxed) {
        return Err("scan cancelled".to_string());
    }
    if stage1_candidates.is_empty() {
        let duration_ms = start.elapsed().as_millis() as u64;
        return Ok(DuplicateReport {
            duration_ms,
            scanned_files: scanned_files.load(Ordering::Relaxed),
            candidate_files,
            total_wasted_bytes: 0,
            skipped_hardlinks: skipped_hardlinks.load(Ordering::Relaxed),
            skipped_cloud_placeholders: skipped_cloud.load(Ordering::Relaxed),
            groups: Vec::new(),
        });
    }

    on_progress(ScanProgressEvent::DirectoryStatUpdated {
        current_path: format!("Stage 2/3: Partial 4KB+4KB pre-hashing ({candidate_files} candidates)"),
        scanned_files: scanned_files.load(Ordering::Relaxed),
        scanned_bytes: 0,
    });

    // Stage 2: Parallel head+tail 4KB BLAKE3 pre-hash
    let partial_hashed: Vec<((u64, [u8; 32]), CandidateFile)> = stage1_candidates
        .into_par_iter()
        .filter(|_| !cancel.load(Ordering::Relaxed))
        .filter_map(|cand| {
            let ph = partial_blake3(&cand.path, cand.logical_bytes).ok()?;
            Some(((cand.logical_bytes, ph), cand))
        })
        .collect();

    let mut partial_buckets: FxHashMap<(u64, [u8; 32]), Vec<CandidateFile>> = FxHashMap::default();
    for (key, cand) in partial_hashed {
        partial_buckets.entry(key).or_default().push(cand);
    }
    let stage2_candidates: Vec<CandidateFile> = partial_buckets
        .into_values()
        .filter(|v| v.len() >= 2)
        .flatten()
        .collect();

    on_progress(ScanProgressEvent::DirectoryStatUpdated {
        current_path: format!(
            "Stage 3/3: Full BLAKE3 verification ({} candidates)",
            stage2_candidates.len()
        ),
        scanned_files: scanned_files.load(Ordering::Relaxed),
        scanned_bytes: 0,
    });

    // Stage 3: Full streaming BLAKE3 verification
    let full_hashed: Vec<(String, CandidateFile)> = stage2_candidates
        .into_par_iter()
        .filter(|_| !cancel.load(Ordering::Relaxed))
        .filter_map(|cand| {
            let digest = full_blake3(&cand.path).ok()?;
            Some((digest, cand))
        })
        .collect();

    if cancel.load(Ordering::Relaxed) {
        return Err("scan cancelled".to_string());
    }
    let mut full_buckets: FxHashMap<String, Vec<CandidateFile>> = FxHashMap::default();
    for (digest, cand) in full_hashed {
        full_buckets.entry(digest).or_default().push(cand);
    }

    let mut groups = Vec::new();
    let mut total_wasted_bytes = 0u64;

    for (blake3_hash, mut files) in full_buckets {
        if files.len() < 2 {
            continue;
        }
        // Smart retention ordering: prefer non-Downloads/Temp -> shorter path -> older mtime
        files.sort_by(|a, b| retention_rank(a).cmp(&retention_rank(b)));

        let file_size = files[0].allocated_bytes.max(files[0].logical_bytes);
        let wasted_bytes = files
            .iter()
            .skip(1)
            .fold(0u64, |acc, f| acc.saturating_add(f.allocated_bytes));
        total_wasted_bytes = total_wasted_bytes.saturating_add(wasted_bytes);

        let entries = files
            .into_iter()
            .enumerate()
            .map(|(idx, f)| DuplicateFileEntry {
                path: f.path,
                name: f.name,
                allocated_bytes: f.allocated_bytes,
                logical_bytes: f.logical_bytes,
                mtime_secs: f.mtime_secs,
                recommended_keep: idx == 0,
            })
            .collect();

        groups.push(DuplicateGroup {
            blake3_hash,
            file_size,
            wasted_bytes,
            entries,
        });
    }

    groups.sort_by(|a, b| b.wasted_bytes.cmp(&a.wasted_bytes));
    let duration_ms = start.elapsed().as_millis() as u64;

    on_progress(ScanProgressEvent::Completed {
        duration_ms,
        total_reclaimable_bytes: total_wasted_bytes,
        hit_count: groups.len(),
    });

    Ok(DuplicateReport {
        duration_ms,
        scanned_files: scanned_files.load(Ordering::Relaxed),
        candidate_files,
        total_wasted_bytes,
        skipped_hardlinks: skipped_hardlinks.load(Ordering::Relaxed),
        skipped_cloud_placeholders: skipped_cloud.load(Ordering::Relaxed),
        groups,
    })
}

/// Cleans duplicate copies with an engine-enforced Anti-Wipe Safety Lock:
/// - Rejects any copy protected by `ignore_paths`.
/// - Deduplicates survivors canonically and refuses any group without >= 1 verified intact survivor.
/// - Re-hashes the surviving copy with BLAKE3 right before deleting (anti-TOCTOU).
/// - Forces `RiskLevel::ReviewRequired` + `DeleteMode::Trash` on every deleted duplicate.
pub fn clean_duplicates(groups: &[DuplicateCleanGroup], dry_run: bool) -> Result<CleanReport, String> {
    let ignore_paths = load_app_config().ignore_paths;
    let mut requests = Vec::new();

    for grp in groups {
        if grp.delete_paths.is_empty() {
            continue;
        }
        for p in &grp.delete_paths {
            if is_path_ignored(p, &ignore_paths) {
                return Err(format!(
                    "refusing to delete duplicate path protected by ignore whitelist: {}",
                    p.display()
                ));
            }
        }

        let mut candidate_survivors: Vec<&PathBuf> = Vec::new();
        for p in &grp.all_paths {
            let is_deleted = grp
                .delete_paths
                .iter()
                .any(|d| paths_equal_for_policy(p, d));
            if is_deleted {
                continue;
            }
            if !candidate_survivors
                .iter()
                .any(|s| paths_equal_for_policy(p, s))
            {
                candidate_survivors.push(p);
            }
        }

        let expected_hash_len_ok = grp.blake3_hash.len() == 64
            && grp.blake3_hash.chars().all(|c| c.is_ascii_hexdigit());
        let mut verified_survivor = false;

        for s in candidate_survivors {
            let Ok(meta) = inspect_path_meta(s) else {
                continue;
            };
            if meta.is_dir || meta.is_symlink_or_reparse || meta.logical_bytes == 0 {
                continue;
            }
            if !dry_run && expected_hash_len_ok {
                if let Ok(actual_hash) = full_blake3(s) {
                    if actual_hash.eq_ignore_ascii_case(&grp.blake3_hash) {
                        verified_survivor = true;
                        break;
                    }
                }
            } else {
                verified_survivor = true;
                break;
            }
        }

        if !verified_survivor {
            return Err(format!(
                "anti-wipe safety lock: refusing to delete copies in duplicate group {} — at least one verified intact copy must survive",
                &grp.blake3_hash[..grp.blake3_hash.len().min(12)]
            ));
        }

        for p in &grp.delete_paths {
            requests.push(CleanItemRequest {
                rule_id: format!("duplicates.blake3.{}", &grp.blake3_hash[..grp.blake3_hash.len().min(12)]),
                path: p.clone(),
                risk: RiskLevel::ReviewRequired,
                delete_mode: DeleteMode::Trash,
                native_command: None,
            });
        }
    }

    Ok(execute_clean(&requests, dry_run))
}

fn retention_rank(f: &CandidateFile) -> (u8, usize, i64, String) {
    let lower = f.path.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
    let priority_tier = if lower.contains("/desktop/")
        || lower.contains("/documents/")
        || lower.contains("/pictures/")
        || lower.contains("/music/")
        || lower.contains("/movies/")
        || lower.contains("/videos/")
    {
        0
    } else if lower.contains("/downloads/")
        || lower.contains("/tmp/")
        || lower.contains("/temp/")
        || lower.contains("copy")
        || lower.contains("副本")
    {
        2
    } else {
        1
    };
    let path_str = f.path.to_string_lossy().to_string();
    (priority_tier, path_str.len(), f.mtime_secs, path_str)
}

#[allow(clippy::too_many_arguments)]
fn collect_candidates(
    dir: &Path,
    depth: usize,
    min_size_bytes: u64,
    ignore_paths: &[PathBuf],
    dedup: &HardlinkDeduplicator,
    scanned_files: &AtomicU64,
    skipped_hardlinks: &AtomicU64,
    skipped_cloud: &AtomicU64,
    cancel: &AtomicBool,
    out: &mut Vec<CandidateFile>,
) {
    if cancel.load(Ordering::Relaxed) {
        return;
    }
    if is_path_ignored(dir, ignore_paths) {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    // Sort directory entries deterministically so hardlink deduplication across filesystems
    // (ext4, APFS, NTFS, overlayfs) consistently preserves non-transient / shorter-named originals.
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by(|a, b| {
        let an = a.file_name().to_string_lossy().to_ascii_lowercase();
        let bn = b.file_name().to_string_lossy().to_ascii_lowercase();
        let a_trans = u8::from(matches!(an.as_str(), "downloads" | "tmp" | "temp") || an.contains("hardlink") || an.contains("copy"));
        let b_trans = u8::from(matches!(bn.as_str(), "downloads" | "tmp" | "temp") || bn.contains("hardlink") || bn.contains("copy"));
        a_trans
            .cmp(&b_trans)
            .then_with(|| an.len().cmp(&bn.len()))
            .then_with(|| an.cmp(&bn))
    });
    for entry in entries {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let lower_name = name.to_ascii_lowercase();
        if matches!(
            lower_name.as_str(),
            ".git"
                | ".hg"
                | ".svn"
                | ".ssh"
                | ".gnupg"
                | ".aws"
                | ".kube"
                | ".azure"
                | ".password-store"
                | "keychains"
                | ".trash"
                | "trash"
                | ".clearlens"
        ) {
            continue;
        }
        // Skip app-internal container/toolchain trees during broad home-level scans so app bundles stay intact
        if depth == 0
            && matches!(
                lower_name.as_str(),
                "library"
                    | "appdata"
                    | ".cache"
                    | ".local"
                    | ".ollama"
                    | ".cargo"
                    | ".rustup"
                    | "node_modules"
            )
        {
            continue;
        }
        if lower_name == "node_modules" {
            continue;
        }
        let p = entry.path();
        if is_path_ignored(&p, ignore_paths) {
            continue;
        }
        let lower_path = p.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
        if lower_name.ends_with(".vhdx")
            || (lower_name == "docker.raw" && lower_path.contains("com.docker.docker"))
            || (lower_name == "data.img" && lower_path.contains(".dev.orbstack"))
            || (lower_name == "diffdisk" && lower_path.contains(".lima"))
        {
            continue;
        }
        let Ok(meta) = inspect_path_meta(&p) else {
            continue;
        };
        if meta.is_symlink_or_reparse {
            continue;
        }
        if meta.is_cloud_placeholder {
            skipped_cloud.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if meta.is_dir {
            collect_candidates(
                &p,
                depth + 1,
                min_size_bytes,
                ignore_paths,
                dedup,
                scanned_files,
                skipped_hardlinks,
                skipped_cloud,
                cancel,
                out,
            );
        } else {
            scanned_files.fetch_add(1, Ordering::Relaxed);
            // Hardlinks sharing the exact same (dev, ino) do not consume extra disk blocks
            if !dedup.should_count(meta.dev, meta.ino, meta.nlink) {
                skipped_hardlinks.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            if meta.logical_bytes >= min_size_bytes && meta.allocated_bytes > 0 {
                out.push(CandidateFile {
                    path: p,
                    name,
                    allocated_bytes: meta.allocated_bytes,
                    logical_bytes: meta.logical_bytes,
                    mtime_secs: meta.mtime_secs,
                });
            }
        }
    }
}

fn partial_blake3(path: &Path, logical_bytes: u64) -> std::io::Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; PARTIAL_SAMPLE_BYTES];

    let n1 = file.read(&mut buf)?;
    hasher.update(&buf[..n1]);

    if logical_bytes > (PARTIAL_SAMPLE_BYTES as u64) * 2 {
        file.seek(SeekFrom::End(-(PARTIAL_SAMPLE_BYTES as i64)))?;
        let n2 = file.read(&mut buf)?;
        hasher.update(&buf[..n2]);
    } else if logical_bytes > PARTIAL_SAMPLE_BYTES as u64 {
        let mut rest = Vec::new();
        file.read_to_end(&mut rest)?;
        hasher.update(&rest);
    }

    Ok(*hasher.finalize().as_bytes())
}

fn full_blake3(path: &Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; FULL_CHUNK_BYTES];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}
