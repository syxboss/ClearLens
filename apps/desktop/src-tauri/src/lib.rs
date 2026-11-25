mod commands;

use clearlens_core::config::paths_equal_for_policy;
use clearlens_core::{DeleteMode, RiskLevel};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct AllowedRuleHit {
    pub rule_id: String,
    pub risk: RiskLevel,
    pub delete_mode: DeleteMode,
    pub native_command: Option<String>,
}

#[derive(Default)]
pub struct AppState {
    active_cancel: Mutex<Option<Arc<AtomicBool>>>,
    allowed_rule_hits: Mutex<HashMap<PathBuf, AllowedRuleHit>>,
    allowed_cold_files: Mutex<HashSet<PathBuf>>,
    allowed_duplicate_paths: Mutex<HashSet<PathBuf>>,
    allowed_orphan_paths: Mutex<HashSet<PathBuf>>,
    allowed_app_paths: Mutex<HashSet<PathBuf>>,
}

impl AppState {
    /// Cancels any in-flight scan and issues a fresh per-scan cancellation token.
    pub fn begin_scan(&self) -> Arc<AtomicBool> {
        let mut guard = self.active_cancel.lock().expect("cancel mutex poisoned");
        if let Some(prev) = guard.take() {
            prev.store(true, Ordering::SeqCst);
        }
        let next = Arc::new(AtomicBool::new(false));
        *guard = Some(next.clone());
        next
    }

    pub fn cancel_current(&self) {
        let guard = self.active_cancel.lock().expect("cancel mutex poisoned");
        if let Some(cur) = guard.as_ref() {
            cur.store(true, Ordering::SeqCst);
        }
    }

    pub fn replace_rule_hits<I: IntoIterator<Item = (PathBuf, AllowedRuleHit)>>(&self, hits: I) {
        let mut guard = self
            .allowed_rule_hits
            .lock()
            .expect("allowed_rule_hits mutex poisoned");
        guard.clear();
        guard.extend(hits);
    }

    pub fn get_allowed_rule_hit(&self, path: &Path) -> Option<AllowedRuleHit> {
        let guard = self
            .allowed_rule_hits
            .lock()
            .expect("allowed_rule_hits mutex poisoned");
        if let Some(found) = guard.get(path) {
            return Some(found.clone());
        }
        guard
            .iter()
            .find(|(k, _)| paths_equal_for_policy(k, path))
            .map(|(_, v)| v.clone())
    }

    pub fn allow_cold_files<I: IntoIterator<Item = PathBuf>>(&self, paths: I) {
        let mut guard = self
            .allowed_cold_files
            .lock()
            .expect("allowed_cold_files mutex poisoned");
        guard.extend(paths);
    }

    pub fn is_cold_file_allowed(&self, path: &Path) -> bool {
        let guard = self
            .allowed_cold_files
            .lock()
            .expect("allowed_cold_files mutex poisoned");
        set_contains_path(&guard, path)
    }

    pub fn replace_duplicate_paths<I: IntoIterator<Item = PathBuf>>(&self, paths: I) {
        let mut guard = self
            .allowed_duplicate_paths
            .lock()
            .expect("allowed_duplicate_paths mutex poisoned");
        guard.clear();
        guard.extend(paths);
    }

    pub fn is_duplicate_path_allowed(&self, path: &Path) -> bool {
        let guard = self
            .allowed_duplicate_paths
            .lock()
            .expect("allowed_duplicate_paths mutex poisoned");
        set_contains_path(&guard, path)
    }

    pub fn replace_uninstaller_paths<O, A>(&self, orphans: O, apps: A)
    where
        O: IntoIterator<Item = PathBuf>,
        A: IntoIterator<Item = PathBuf>,
    {
        {
            let mut guard = self
                .allowed_orphan_paths
                .lock()
                .expect("allowed_orphan_paths mutex poisoned");
            guard.clear();
            guard.extend(orphans);
        }
        {
            let mut guard = self
                .allowed_app_paths
                .lock()
                .expect("allowed_app_paths mutex poisoned");
            guard.clear();
            guard.extend(apps);
        }
    }

    pub fn is_orphan_path_allowed(&self, path: &Path) -> bool {
        let guard = self
            .allowed_orphan_paths
            .lock()
            .expect("allowed_orphan_paths mutex poisoned");
        set_contains_path(&guard, path)
    }

    pub fn is_app_path_allowed(&self, path: &Path) -> bool {
        let guard = self
            .allowed_app_paths
            .lock()
            .expect("allowed_app_paths mutex poisoned");
        set_contains_path(&guard, path)
    }
}

fn set_contains_path(set: &HashSet<PathBuf>, path: &Path) -> bool {
    set.contains(path) || set.iter().any(|k| paths_equal_for_policy(k, path))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::get_disk_overview,
            commands::start_rule_scan,
            commands::run_clean,
            commands::start_space_lens,
            commands::start_duplicate_scan,
            commands::clean_duplicate_groups,
            commands::scan_uninstaller,
            commands::clean_orphans,
            commands::uninstall_app,
            commands::cancel_scan,
            commands::get_builtin_rules,
            commands::get_audit_history,
            commands::get_app_config,
            commands::update_ignore_list,
            commands::update_workspace_roots,
            commands::thin_local_snapshots,
            commands::scan_virtual_disks,
            commands::reveal_in_folder,
            commands::open_fda_settings,
        ])
        .run(tauri::generate_context!())
        .expect("error while running ClearLens Tauri application");
}
