pub mod audit;
pub mod cleaner;
pub mod config;
pub mod duplicates;
pub mod lens;
pub mod models;
pub mod platform;
pub mod rules;
pub mod safety;
pub mod uninstaller;
pub mod vdisk;

pub use audit::{append_audit_record, read_audit_history};
pub use cleaner::{execute_clean, execute_clean_with_elevation};
pub use config::{
    load_app_config, save_app_config, update_default_stale_days, update_ignore_list,
    update_workspace_roots,
};
pub use duplicates::{clean_duplicates, scan_duplicates};
pub use lens::scan_space_lens;
pub use models::*;
pub use platform::elevation::{execute_elevation_request, run_elevation_worker_files};
pub use platform::thin_local_snapshots;
pub use rules::{load_all_rules, run_rule_scan, validate_rule_file, validate_toml_str};
pub use safety::{validate_rule_pattern, ProtectedBlocklist, SafetyError};
pub use uninstaller::{clean_orphan_paths, scan_apps_and_orphans, uninstall_app_paths};
pub use vdisk::scan_virtual_disks;
