use crate::config::{dir_contains_ignored, is_path_ignored, load_app_config};
use crate::models::{ColdFileEntry, ScanProgressEvent, SpaceLensReport, SpaceNode};
use crate::platform::inspect_path_meta;
use crate::safety::HardlinkDeduplicator;
use rayon::prelude::*;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_SERIALIZED_DEPTH: usize = 4;
const MAX_CHILDREN_PER_NODE: usize = 36;
const MAX_COLD_FILES_HEAP: usize = 200;

#[derive(Clone)]
struct RankedColdFile(ColdFileEntry);

impl PartialEq for RankedColdFile {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}

impl Eq for RankedColdFile {}

impl Ord for RankedColdFile {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .allocated_bytes
            .cmp(&other.0.allocated_bytes)
            .then_with(|| self.0.inactive_days.cmp(&other.0.inactive_days))
            .then_with(|| self.0.path.cmp(&other.0.path))
    }
}

impl PartialOrd for RankedColdFile {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

pub fn scan_space_lens<F>(
    root: &Path,
    min_cold_bytes: u64,
    cold_days: u32,
    cancel: &AtomicBool,
    mut on_progress: F,
) -> Result<SpaceLensReport, String>
where
    F: FnMut(ScanProgressEvent) + Send,
{
    if !root.exists() {
        return Err(format!("path does not exist: {}", root.display()));
    }
    let start = Instant::now();
    let dedup = HardlinkDeduplicator::default();
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let counters = LensCounters::default();
    let ignore_paths = load_app_config().ignore_paths;
    let cold_collector =
        Mutex::new(BinaryHeap::<Reverse<RankedColdFile>>::with_capacity(MAX_COLD_FILES_HEAP + 1));
    let progress_gate = Mutex::new((Instant::now(), &mut on_progress));

    let root_node = walk_lens_node(
        root,
        0,
        min_cold_bytes,
        cold_days,
        now_secs,
        &dedup,
        &ignore_paths,
        &counters,
        &cold_collector,
        &progress_gate,
        cancel,
    );

    if cancel.load(Ordering::Relaxed) {
        return Err("scan cancelled".to_string());
    }

    let scanned_files = counters.files.load(Ordering::Relaxed);
    let scanned_bytes = root_node.allocated_bytes;
    let heap = cold_collector
        .into_inner()
        .expect("cold collector mutex poisoned");
    let mut cold_files: Vec<ColdFileEntry> = heap.into_iter().map(|Reverse(r)| r.0).collect();
    cold_files.sort_by(|a, b| b.allocated_bytes.cmp(&a.allocated_bytes));

    let duration_ms = start.elapsed().as_millis() as u64;
    if let Ok(mut guard) = progress_gate.lock() {
        (guard.1)(ScanProgressEvent::DirectoryStatUpdated {
            current_path: root.display().to_string(),
            scanned_files,
            scanned_bytes,
        });
        (guard.1)(ScanProgressEvent::Completed {
            duration_ms,
            total_reclaimable_bytes: scanned_bytes,
            hit_count: cold_files.len(),
        });
    }

    Ok(SpaceLensReport {
        root: root_node,
        cold_files,
        duration_ms,
        skipped_cloud_placeholders: counters.cloud.load(Ordering::Relaxed),
        skipped_symlinks: counters.symlinks.load(Ordering::Relaxed),
        skipped_permission_errors: counters.perm_errors.load(Ordering::Relaxed),
    })
}

#[derive(Default)]
struct LensCounters {
    files: AtomicU64,
    bytes: AtomicU64,
    cloud: AtomicU64,
    symlinks: AtomicU64,
    perm_errors: AtomicU64,
}

#[allow(clippy::too_many_arguments)]
fn walk_lens_node<F>(
    path: &Path,
    depth: usize,
    min_cold_bytes: u64,
    cold_days: u32,
    now_secs: i64,
    dedup: &HardlinkDeduplicator,
    ignore_paths: &[PathBuf],
    counters: &LensCounters,
    cold_collector: &Mutex<BinaryHeap<Reverse<RankedColdFile>>>,
    progress_gate: &Mutex<(Instant, &mut F)>,
    cancel: &AtomicBool,
) -> SpaceNode
where
    F: FnMut(ScanProgressEvent) + Send,
{
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| path.display().to_string());

    if cancel.load(Ordering::Relaxed) {
        return SpaceNode {
            name,
            path: path.to_path_buf(),
            allocated_bytes: 0,
            file_count: 0,
            is_dir: true,
            is_synthetic_other: false,
            has_more_children: false,
            children: Vec::new(),
        };
    }

    if depth <= 2 {
        if let Ok(mut guard) = progress_gate.try_lock() {
            if guard.0.elapsed() >= Duration::from_millis(100) {
                guard.0 = Instant::now();
                (guard.1)(ScanProgressEvent::DirectoryStatUpdated {
                    current_path: path.display().to_string(),
                    scanned_files: counters.files.load(Ordering::Relaxed),
                    scanned_bytes: counters.bytes.load(Ordering::Relaxed),
                });
            }
        }
    }

    let entries: Vec<_> = match fs::read_dir(path) {
        Ok(rd) => rd.flatten().map(|e| e.path()).collect(),
        Err(e) => {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                counters.perm_errors.fetch_add(1, Ordering::Relaxed);
            }
            return SpaceNode {
                name,
                path: path.to_path_buf(),
                allocated_bytes: 0,
                file_count: 0,
                is_dir: true,
                is_synthetic_other: false,
                has_more_children: false,
                children: Vec::new(),
            };
        }
    };

    let children_nodes: Vec<SpaceNode> = entries
        .par_iter()
        .filter(|_| !cancel.load(Ordering::Relaxed))
        .filter_map(|child_path| {
            let Ok(meta) = inspect_path_meta(child_path) else {
                return None;
            };
            if meta.is_symlink_or_reparse {
                counters.symlinks.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            if meta.is_cloud_placeholder {
                counters.cloud.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            if meta.is_dir {
                Some(walk_lens_node(
                    child_path,
                    depth + 1,
                    min_cold_bytes,
                    cold_days,
                    now_secs,
                    dedup,
                    ignore_paths,
                    counters,
                    cold_collector,
                    progress_gate,
                    cancel,
                ))
            } else {
                if !dedup.should_count(meta.dev, meta.ino, meta.nlink) {
                    return None;
                }
                counters.files.fetch_add(1, Ordering::Relaxed);
                counters.bytes.fetch_add(meta.allocated_bytes, Ordering::Relaxed);
                let last_touch = meta.atime_secs.max(meta.mtime_secs);
                let inactive_days = if now_secs > last_touch && last_touch > 0 {
                    ((now_secs - last_touch) / 86_400) as u64
                } else {
                    0
                };
                if meta.allocated_bytes >= min_cold_bytes
                    && inactive_days >= cold_days as u64
                    && !is_path_ignored(child_path, ignore_paths)
                    && !dir_contains_ignored(child_path, ignore_paths)
                    && crate::safety::ProtectedBlocklist::check_path(child_path).is_ok()
                {
                    let fname = child_path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();
                    let mut guard = cold_collector.lock().expect("cold collector poisoned");
                    let candidate = RankedColdFile(ColdFileEntry {
                        path: child_path.clone(),
                        name: fname,
                        allocated_bytes: meta.allocated_bytes,
                        last_modified_ts: meta.mtime_secs,
                        inactive_days,
                    });
                    if guard.len() < MAX_COLD_FILES_HEAP {
                        guard.push(Reverse(candidate));
                    } else if let Some(Reverse(smallest)) = guard.peek() {
                        if candidate > *smallest {
                            guard.pop();
                            guard.push(Reverse(candidate));
                        }
                    }
                }
                Some(SpaceNode {
                    name: child_path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default(),
                    path: child_path.clone(),
                    allocated_bytes: meta.allocated_bytes,
                    file_count: 1,
                    is_dir: false,
                    is_synthetic_other: false,
                    has_more_children: false,
                    children: Vec::new(),
                })
            }
        })
        .collect();

    let mut total_bytes = 0u64;
    let mut total_files = 0u64;
    for ch in &children_nodes {
        total_bytes = total_bytes.saturating_add(ch.allocated_bytes);
        total_files = total_files.saturating_add(ch.file_count);
    }

    let has_more_children = depth >= MAX_SERIALIZED_DEPTH && !children_nodes.is_empty();
    let kept_children = if depth >= MAX_SERIALIZED_DEPTH {
        Vec::new()
    } else {
        compact_children(path, children_nodes, total_bytes)
    };

    SpaceNode {
        name,
        path: path.to_path_buf(),
        allocated_bytes: total_bytes,
        file_count: total_files,
        is_dir: true,
        is_synthetic_other: false,
        has_more_children,
        children: kept_children,
    }
}

fn compact_children(
    parent_path: &Path,
    mut nodes: Vec<SpaceNode>,
    parent_bytes: u64,
) -> Vec<SpaceNode> {
    nodes.retain(|n| n.allocated_bytes > 0);
    nodes.sort_by(|a, b| b.allocated_bytes.cmp(&a.allocated_bytes));

    if nodes.len() <= MAX_CHILDREN_PER_NODE {
        return nodes;
    }

    let min_significant = parent_bytes / 300;
    let mut kept = Vec::new();
    let mut other_bytes = 0u64;
    let mut other_files = 0u64;

    for (idx, n) in nodes.into_iter().enumerate() {
        if idx < MAX_CHILDREN_PER_NODE && (n.allocated_bytes >= min_significant || idx < 12) {
            kept.push(n);
        } else {
            other_bytes = other_bytes.saturating_add(n.allocated_bytes);
            other_files = other_files.saturating_add(n.file_count);
        }
    }

    if other_bytes > 0 {
        kept.push(SpaceNode {
            name: "Other items".to_string(),
            path: parent_path.join("__clearlens_other__"),
            allocated_bytes: other_bytes,
            file_count: other_files,
            is_dir: false,
            is_synthetic_other: true,
            has_more_children: false,
            children: Vec::new(),
        });
    }

    kept
}
