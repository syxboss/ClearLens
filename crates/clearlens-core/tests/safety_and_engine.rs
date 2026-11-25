#![allow(deprecated)]

use clearlens_core::rules::smart_scanners::measure_dir_physical;
use clearlens_core::safety::HardlinkDeduplicator;
use clearlens_core::{
    execute_clean, load_all_rules, read_audit_history, run_rule_scan, scan_space_lens,
    validate_rule_pattern, CleanItemRequest, DeleteMode, ProtectedBlocklist, RiskLevel,
    ScanOptions, TargetPlatform,
};
use filetime::{set_file_mtime, FileTime};
use std::fs;
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};
use tempfile::tempdir;

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn embedded_rule_pack_loads_and_validates_over_25_rules() {
    let files = load_all_rules().expect("embedded TOML rules should parse and validate");
    let total_rules: usize = files.iter().map(|f| f.rules.len()).sum();
    assert!(
        total_rules >= 25,
        "expected >= 25 built-in rules, got {total_rules}"
    );
}

#[test]
fn blocklist_rejects_sensitive_and_user_asset_paths() {
    let _g = ENV_LOCK.lock().unwrap();
    let dir = tempdir().unwrap();
    std::env::set_var("HOME", dir.path());

    assert!(ProtectedBlocklist::check_path(&dir.path().join(".ssh/id_ed25519")).is_err());
    assert!(ProtectedBlocklist::check_path(&dir.path().join("Library/Keychains/login.keychain-db")).is_err());
    assert!(ProtectedBlocklist::check_path(&dir.path().join("Projects/app/.git/objects")).is_err());
    assert!(ProtectedBlocklist::check_path(&dir.path().join("Desktop/secret.txt")).is_err());
    assert!(ProtectedBlocklist::check_path(&dir.path().join("Documents/report.docx")).is_err());
    assert!(ProtectedBlocklist::check_path(&dir.path().join("Documents/WeChat Files/wxid_1/FileStorage/File/2026-11/contract.pdf")).is_err());

    // Explicit app cache inside Documents IS permitted
    assert!(ProtectedBlocklist::check_path(&dir.path().join("Documents/WeChat Files/wxid_1/FileStorage/Cache/2026-11")).is_ok());

    // Broad dangerous TOML rule globs must be rejected
    assert!(validate_rule_pattern("~/*").is_err());
    assert!(validate_rule_pattern("~/Documents/**").is_err());
    assert!(validate_rule_pattern("~/.ssh/**").is_err());
    assert!(validate_rule_pattern("~/Library/Caches/Google/Chrome/*/Cache/**").is_ok());
}

#[cfg(unix)]
#[test]
fn symlink_trap_never_counts_or_deletes_external_target() {
    let _g = ENV_LOCK.lock().unwrap();
    let dir = tempdir().unwrap();
    std::env::set_var("HOME", dir.path());

    let precious_dir = dir.path().join("PreciousExternal");
    fs::create_dir_all(&precious_dir).unwrap();
    let precious_file = precious_dir.join("master.db");
    fs::write(&precious_file, vec![b'X'; 32_768]).unwrap();

    let cache_dir = dir.path().join("Library/Caches/TestApp");
    fs::create_dir_all(&cache_dir).unwrap();
    fs::write(cache_dir.join("temp.bin"), vec![b'A'; 4096]).unwrap();

    // Symlink inside cache pointing outside to PreciousExternal
    std::os::unix::fs::symlink(&precious_dir, cache_dir.join("trap_link")).unwrap();

    let dedup = HardlinkDeduplicator::default();
    let (bytes, files) = measure_dir_physical(&cache_dir, &dedup);
    assert_eq!(files, 1, "only real file temp.bin should be counted");
    assert!(bytes < 16_384, "precious external 32KB must not be counted");

    let report = execute_clean(
        &[CleanItemRequest {
            rule_id: "test.symlink".into(),
            path: cache_dir.clone(),
            risk: RiskLevel::Safe,
            delete_mode: DeleteMode::Permanent,
            native_command: None,
        }],
        false,
    );
    assert_eq!(report.succeeded_count, 1);
    assert!(!cache_dir.exists(), "cache dir should be removed");
    assert!(
        precious_file.exists(),
        "precious file behind symlink MUST remain untouched!"
    );
}

#[test]
fn hardlinks_are_deduplicated_during_physical_accounting() {
    let dir = tempdir().unwrap();
    let f1 = dir.path().join("blob_a.bin");
    let f2 = dir.path().join("blob_b.bin");
    let f3 = dir.path().join("blob_c.bin");
    fs::write(&f1, vec![b'Z'; 65_536]).unwrap();
    fs::hard_link(&f1, &f2).unwrap();
    fs::hard_link(&f1, &f3).unwrap();

    let dedup = HardlinkDeduplicator::default();
    let (bytes, files) = measure_dir_physical(dir.path(), &dedup);
    assert_eq!(files, 1, "3 hardlinks to same inode should count once");
    assert!(bytes >= 65_536 && bytes < 131_072);
}

#[test]
fn icloud_stub_placeholders_are_skipped_by_space_lens() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("real.bin"), vec![b'R'; 16_384]).unwrap();
    fs::write(dir.path().join(".BigVideo.mov.icloud"), vec![b'C'; 8192]).unwrap();

    let cancel = AtomicBool::new(false);
    let report = scan_space_lens(dir.path(), 1, 0, &cancel, |_| {}).unwrap();
    assert_eq!(report.skipped_cloud_placeholders, 1);
    assert_eq!(report.root.file_count, 1);
}

#[test]
fn cold_project_scanner_only_flags_stale_projects_and_respects_dry_run_and_audit() {
    let _g = ENV_LOCK.lock().unwrap();
    let dir = tempdir().unwrap();
    std::env::set_var("HOME", dir.path());
    std::env::set_var("XDG_DATA_HOME", dir.path().join(".local/share"));

    let workspace = dir.path().join("Projects");
    let stale_proj = workspace.join("old-web-app");
    let active_proj = workspace.join("active-web-app");
    fs::create_dir_all(stale_proj.join("node_modules/lodash")).unwrap();
    fs::create_dir_all(active_proj.join("node_modules/react")).unwrap();

    let stale_pkg = stale_proj.join("package.json");
    let stale_src = stale_proj.join("index.js");
    let stale_nm_file = stale_proj.join("node_modules/lodash/index.js");
    fs::write(&stale_pkg, "{}").unwrap();
    fs::write(&stale_src, "console.log(1)").unwrap();
    fs::write(&stale_nm_file, vec![b'N'; 16_384]).unwrap();

    fs::write(active_proj.join("package.json"), "{}").unwrap();
    fs::write(active_proj.join("node_modules/react/index.js"), vec![b'R'; 16_384]).unwrap();

    // Backdate stale project files by 45 days
    let old_time = FileTime::from_system_time(
        SystemTime::now() - Duration::from_secs(45 * 86_400),
    );
    set_file_mtime(&stale_pkg, old_time).unwrap();
    set_file_mtime(&stale_src, old_time).unwrap();
    set_file_mtime(&stale_proj, old_time).unwrap();

    // Also create a Downloads old .dmg (>60d) to verify ReviewRequired -> forced Trash routing
    let downloads = dir.path().join("Downloads");
    fs::create_dir_all(&downloads).unwrap();
    let old_dmg = downloads.join("Xcode_old.dmg");
    fs::write(&old_dmg, vec![b'D'; 32_768]).unwrap();
    let dmg_old_time = FileTime::from_system_time(
        SystemTime::now() - Duration::from_secs(90 * 86_400),
    );
    set_file_mtime(&old_dmg, dmg_old_time).unwrap();

    let opts = ScanOptions {
        platform: TargetPlatform::MacOs,
        categories: None,
        stale_days: 30,
        workspace_roots: vec![workspace],
        ignore_paths: Vec::new(),
    };

    let cancel = AtomicBool::new(false);
    let report = run_rule_scan(&opts, &cancel, |_| {}).unwrap();

    assert!(
        report.hits.iter().any(|h| h.path == stale_proj.join("node_modules")),
        "stale project node_modules should be flagged"
    );
    assert!(
        !report.hits.iter().any(|h| h.path == active_proj.join("node_modules")),
        "active project node_modules must NOT be flagged"
    );
    assert!(
        report.hits.iter().any(|h| h.path == old_dmg && h.risk == RiskLevel::ReviewRequired && !h.default_checked),
        "old .dmg should be flagged as ReviewRequired and unchecked by default"
    );

    // Dry-run must leave files untouched
    let dry_items: Vec<CleanItemRequest> = report
        .hits
        .iter()
        .map(|h| CleanItemRequest {
            rule_id: h.rule_id.clone(),
            path: h.path.clone(),
            risk: h.risk,
            delete_mode: h.delete_mode,
            native_command: h.native_command.clone(),
        })
        .collect();
    let dry_res = execute_clean(&dry_items, true);
    assert!(dry_res.dry_run);
    assert!(stale_proj.join("node_modules").exists());
    assert!(old_dmg.exists());

    // Actual clean: stale node_modules is permanently deleted; ReviewRequired old_dmg is forced to Trash even if Permanent was requested!
    let real_items = vec![
        CleanItemRequest {
            rule_id: "dev.cold_project_artifacts".into(),
            path: stale_proj.join("node_modules"),
            risk: RiskLevel::Recreatable,
            delete_mode: DeleteMode::Permanent,
            native_command: None,
        },
        CleanItemRequest {
            rule_id: "system.downloads_old_installers".into(),
            path: old_dmg.clone(),
            risk: RiskLevel::ReviewRequired,
            delete_mode: DeleteMode::Permanent, // Intentionally ask for Permanent; engine MUST override to Trash!
            native_command: None,
        },
    ];
    let clean_res = execute_clean(&real_items, false);
    assert_eq!(clean_res.succeeded_count, 2);
    assert_eq!(clean_res.outcomes[1].actual_mode, DeleteMode::Trash);
    assert!(!stale_proj.join("node_modules").exists());
    assert!(!old_dmg.exists());
    assert!(active_proj.join("node_modules").exists());

    let history = read_audit_history(10);
    assert!(history.len() >= 2, "audit log should record cleaned items");
}

#[test]
fn blocklist_blocks_dotdot_traversal_windows_prefixes_and_ancestor_symlinks() {
    let _g = ENV_LOCK.lock().unwrap();
    let dir = tempdir().unwrap();
    std::env::set_var("HOME", dir.path());

    let desktop = dir.path().join("Desktop");
    let caches = dir.path().join("Library/Caches");
    fs::create_dir_all(&desktop).unwrap();
    fs::create_dir_all(&caches).unwrap();
    fs::write(desktop.join("secret.pdf"), b"PRECIOUS").unwrap();

    // 1. `..` parent traversal bypass attempt MUST be blocked
    let dotdot_bypass = caches.join("../../Desktop/secret.pdf");
    assert!(
        ProtectedBlocklist::check_path(&dotdot_bypass).is_err(),
        "`..` traversal into Desktop MUST be rejected"
    );

    // 2. Windows & Unix system prefix coverage
    assert!(ProtectedBlocklist::check_path(std::path::Path::new("C:/Windows/Fonts/arial.ttf")).is_err());
    assert!(ProtectedBlocklist::check_path(std::path::Path::new("C:/Windows/explorer.exe")).is_err());
    assert!(ProtectedBlocklist::check_path(std::path::Path::new("C:/Program Files/Common Files/shared.dll")).is_err());
    assert!(ProtectedBlocklist::check_path(std::path::Path::new("/etc/passwd")).is_err());
    // Allowed scoped caches inside Windows / Steam must still pass
    assert!(ProtectedBlocklist::check_path(std::path::Path::new(
        "C:/Windows/SoftwareDistribution/Download/pkg.cab"
    ))
    .is_ok());
    assert!(ProtectedBlocklist::check_path(std::path::Path::new(
        "C:/Program Files (x86)/Steam/steamapps/shadercache/730"
    ))
    .is_ok());

    // 3. Ancestor symlink pointing into Desktop MUST be blocked
    #[cfg(unix)]
    {
        let link_dir = caches.join("sneaky_link");
        std::os::unix::fs::symlink(&desktop, &link_dir).unwrap();
        assert!(
            ProtectedBlocklist::check_path(&link_dir.join("secret.pdf")).is_err(),
            "ancestor symlink into Desktop MUST be blocked"
        );
    }
}

#[test]
fn glob_anchor_preserves_container_root_and_enforces_clean_time_toctou() {
    let _g = ENV_LOCK.lock().unwrap();
    let dir = tempdir().unwrap();
    std::env::set_var("HOME", dir.path());

    // `system.user_logs` targets `~/Library/Logs/**` with `min_age_days = 7`
    let logs_root = dir.path().join("Library/Logs");
    fs::create_dir_all(&logs_root).unwrap();
    let old_log = logs_root.join("stale.log");
    fs::write(&old_log, vec![b'L'; 8192]).unwrap();
    let ten_days_ago = FileTime::from_system_time(SystemTime::now() - Duration::from_secs(10 * 86_400));
    set_file_mtime(&old_log, ten_days_ago).unwrap();

    let opts = ScanOptions {
        platform: TargetPlatform::MacOs,
        categories: Some(vec!["system".into()]),
        stale_days: 30,
        workspace_roots: Vec::new(),
        ignore_paths: Vec::new(),
    };
    let cancel = AtomicBool::new(false);
    let report = run_rule_scan(&opts, &cancel, |_| {}).unwrap();
    let hit = report
        .hits
        .iter()
        .find(|h| h.rule_id == "system.user_logs")
        .expect("system.user_logs should match stale.log");
    assert_eq!(hit.path, logs_root);

    // Simulate TOCTOU: a brand-new log file is written AFTER scan finishes, right before execute_clean!
    let fresh_log = logs_root.join("brand_new_active.log");
    fs::write(&fresh_log, b"ACTIVE_STREAM").unwrap();

    let clean_res = execute_clean(
        &[CleanItemRequest {
            rule_id: hit.rule_id.clone(),
            path: hit.path.clone(),
            risk: hit.risk,
            delete_mode: hit.delete_mode,
            native_command: None,
        }],
        false,
    );
    assert_eq!(clean_res.succeeded_count, 1);
    assert!(!old_log.exists(), "10-day-old log should be removed");
    assert!(
        fresh_log.exists(),
        "brand-new file created after scan MUST be preserved by clean-time mtime check"
    );
    assert!(
        logs_root.exists(),
        "`~/Library/Logs` container root directory itself MUST remain intact"
    );
}

#[test]
fn verbatim_windows_paths_secondary_drives_and_unsafe_custom_rules_blocked() {
    let _g = ENV_LOCK.lock().unwrap();
    let dir = tempdir().unwrap();
    std::env::set_var("HOME", dir.path());

    // 1. Windows \\?\ verbatim paths & secondary drive roots MUST still trigger ProtectedBlocklist
    assert!(ProtectedBlocklist::check_path(std::path::Path::new(
        r"\\?\C:\Windows\System32\cmd.exe"
    ))
    .is_err());
    assert!(ProtectedBlocklist::check_path(std::path::Path::new(
        "//?/C:/Program Files/App/a.dll"
    ))
    .is_err());
    assert!(ProtectedBlocklist::check_path(std::path::Path::new("D:/")).is_err());
    assert!(ProtectedBlocklist::check_path(std::path::Path::new(
        "D:/Windows/System32/ntdll.dll"
    ))
    .is_err());
    assert!(ProtectedBlocklist::check_path(std::path::Path::new(
        "E:/ProgramData/Microsoft/foo"
    ))
    .is_err());

    // Allowed scoped caches behind verbatim or secondary drives MUST pass
    assert!(ProtectedBlocklist::check_path(std::path::Path::new(
        r"\\?\C:\Windows\SoftwareDistribution\Download\pkg.cab"
    ))
    .is_ok());
    assert!(ProtectedBlocklist::check_path(std::path::Path::new(
        "D:/Program Files (x86)/Steam/steamapps/shadercache/730"
    ))
    .is_ok());

    // 2. Dangerous custom TOML patterns MUST be rejected while safe OS tokens remain accepted
    assert!(validate_rule_pattern("C:/Windows/System32/**").is_err());
    assert!(validate_rule_pattern("/etc/**").is_err());
    assert!(validate_rule_pattern("~/Caches/../Desktop/**").is_err());
    assert!(validate_rule_pattern("D:/**").is_err());
    assert!(validate_rule_pattern("%WINDIR%/SoftwareDistribution/Download/**").is_ok());
    assert!(validate_rule_pattern("%PROGRAMFILES(X86)%/Steam/steamapps/shadercache/**").is_ok());
}

#[test]
fn ignore_whitelist_protects_nested_subdirectories_and_zero_byte_toctou_accounting() {
    let _g = ENV_LOCK.lock().unwrap();
    let dir = tempdir().unwrap();
    std::env::set_var("HOME", dir.path());
    std::env::set_var("XDG_DATA_HOME", dir.path().join(".local/share"));

    let logs_root = dir.path().join("Library/Logs");
    let clean_me = logs_root.join("CleanMe");
    let keep_ignored = logs_root.join("KeepIgnored");
    fs::create_dir_all(&clean_me).unwrap();
    fs::create_dir_all(&keep_ignored).unwrap();

    let old_cleanable = clean_me.join("old.log");
    let old_ignored = keep_ignored.join("precious.log");
    fs::write(&old_cleanable, vec![b'C'; 8192]).unwrap();
    fs::write(&old_ignored, vec![b'I'; 16_384]).unwrap();

    let ten_days_ago =
        FileTime::from_system_time(SystemTime::now() - Duration::from_secs(10 * 86_400));
    set_file_mtime(&old_cleanable, ten_days_ago).unwrap();
    set_file_mtime(&old_ignored, ten_days_ago).unwrap();
    set_file_mtime(&clean_me, ten_days_ago).unwrap();
    set_file_mtime(&keep_ignored, ten_days_ago).unwrap();

    clearlens_core::update_ignore_list(keep_ignored.clone(), false).unwrap();

    let cfg = clearlens_core::load_app_config();
    let opts = ScanOptions {
        platform: TargetPlatform::MacOs,
        categories: Some(vec!["system".into()]),
        stale_days: 30,
        workspace_roots: Vec::new(),
        ignore_paths: cfg.ignore_paths,
    };
    let cancel = AtomicBool::new(false);
    let report = run_rule_scan(&opts, &cancel, |_| {}).unwrap();
    assert!(
        report.hits.iter().any(|h| h.path == clean_me),
        "CleanMe subdirectory should be matched"
    );
    assert!(
        report.total_reclaimable_bytes < 16_384,
        "ignored KeepIgnored/precious.log (16KB) MUST NOT be counted in total_reclaimable_bytes (got {})",
        report.total_reclaimable_bytes
    );

    // Direct execute_clean against parent `~/Library/Logs` MUST preserve `KeepIgnored` in both dry-run and real clean!
    let dry_res = execute_clean(
        &[CleanItemRequest {
            rule_id: "system.user_logs".into(),
            path: logs_root.clone(),
            risk: RiskLevel::Safe,
            delete_mode: DeleteMode::Permanent,
            native_command: None,
        }],
        true,
    );
    assert!(
        dry_res.total_freed_bytes < 16_384,
        "dry-run byte estimate MUST exclude ignored child directories (got {})",
        dry_res.total_freed_bytes
    );

    let real_res = execute_clean(
        &[CleanItemRequest {
            rule_id: "system.user_logs".into(),
            path: logs_root.clone(),
            risk: RiskLevel::Safe,
            delete_mode: DeleteMode::Permanent,
            native_command: None,
        }],
        false,
    );
    assert_eq!(real_res.succeeded_count, 1);
    assert!(!old_cleanable.exists(), "CleanMe/old.log should be deleted");
    assert!(
        old_ignored.exists(),
        "KeepIgnored/precious.log MUST remain untouched when parent Library/Logs is cleaned!"
    );
    assert!(logs_root.exists(), "Library/Logs root MUST remain intact");

    // TOCTOU zero-byte regression check: fresh file created right before clean MUST survive and report 0 bytes freed
    let fresh = logs_root.join("just_created.log");
    fs::write(&fresh, vec![b'F'; 4096]).unwrap();
    let zero_res = execute_clean(
        &[CleanItemRequest {
            rule_id: "system.user_logs".into(),
            path: logs_root.clone(),
            risk: RiskLevel::Safe,
            delete_mode: DeleteMode::Permanent,
            native_command: None,
        }],
        false,
    );
    assert!(fresh.exists(), "newly created file MUST be skipped by min_age_days=7 check");
    assert!(old_ignored.exists());
    assert_eq!(
        zero_res.total_freed_bytes, 0,
        "when all files inside dir are skipped at clean time, freed_bytes MUST accurately be 0"
    );

    let _ = clearlens_core::update_ignore_list(keep_ignored, true);
}

#[test]
fn pass3_credentials_browser_secrets_vdisks_and_case_insensitive_guards() {
    let _g = ENV_LOCK.lock().unwrap();
    let dir = tempdir().unwrap();
    std::env::set_var("HOME", dir.path());
    let xdg = dir.path().join(".local/share");
    std::env::set_var("XDG_DATA_HOME", &xdg);

    // 1. Credentials, ClearLens state, browser secrets, and virtual disk images MUST be blocked at engine level
    for blocked in [
        dir.path().join(".npmrc"),
        dir.path().join(".docker/config.json"),
        dir.path().join(".config/gh/hosts.yml"),
        dir.path().join(".clearlens/audit.jsonl"),
        dir.path().join("Library/Application Support/Google/Chrome/Default/Cookies"),
        dir.path().join("Library/Application Support/Google/Chrome/Default/Login Data"),
        dir.path().join(".mozilla/firefox/p1/key4.db"),
        std::path::PathBuf::from("C:/Users/Alice/AppData/Local/Docker/wsl/data/ext4.vhdx"),
        dir.path().join("Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw"),
    ] {
        assert!(
            ProtectedBlocklist::check_path(&blocked).is_err(),
            "expected ProtectedBlocklist to reject {}",
            blocked.display()
        );
    }
    assert!(
        ProtectedBlocklist::check_path(
            &dir.path().join("Library/Caches/Google/Chrome/Default/Cache/data_0")
        )
        .is_ok(),
        "real Chrome cache entry must remain allowed"
    );

    // 2. Dangerous custom TOML patterns using usernames or top-level AppData/Library wildcards MUST be rejected
    for bad_pat in [
        "/Users/alice/Desktop/**",
        "C:/Users/*/Documents/**",
        "~/Library/**",
        "%APPDATA%/**",
        "**/*.vhdx",
    ] {
        assert!(
            validate_rule_pattern(bad_pat).is_err(),
            "expected validate_rule_pattern to reject '{bad_pat}'"
        );
    }

    // 3. Normalized case-insensitive prefix matching
    assert!(clearlens_core::config::path_starts_with_normalized(
        std::path::Path::new("/Users/Alice/Library/Logs/Keep"),
        std::path::Path::new("/users/alice/library/logs"),
        true
    ));
    assert!(clearlens_core::config::path_starts_with_normalized(
        std::path::Path::new(r"\\?\C:\Users\Alice\AppData"),
        std::path::Path::new("c:/users/alice"),
        true
    ));

    // 4. Case-insensitive `[rules.exclude]` matching (using `creative.jianying_capcut.cache` excludes `**/Projects/**` & `**/*.json`)
    let capcut_cache = dir.path().join("Movies/CapCut/User Data/Cache");
    let capcut_proj = capcut_cache.join("PROJECTS");
    fs::create_dir_all(&capcut_proj).unwrap();
    let keep_proj_file = capcut_proj.join("draft.dat");
    let keep_json = capcut_cache.join("state.JSON");
    let clean_render = capcut_cache.join("render.tmp");
    fs::write(&keep_proj_file, vec![b'P'; 4096]).unwrap();
    fs::write(&keep_json, br#"{"draft":1}"#).unwrap();
    fs::write(&clean_render, vec![b'R'; 8192]).unwrap();
    let old_time = FileTime::from_system_time(SystemTime::now() - Duration::from_secs(14 * 86_400));
    set_file_mtime(&keep_proj_file, old_time).unwrap();
    set_file_mtime(&keep_json, old_time).unwrap();
    set_file_mtime(&clean_render, old_time).unwrap();

    let res = execute_clean(
        &[CleanItemRequest {
            rule_id: "creative.jianying_capcut.cache".into(),
            path: capcut_cache.clone(),
            risk: RiskLevel::Recreatable,
            delete_mode: DeleteMode::Permanent,
            native_command: None,
        }],
        false,
    );
    assert_eq!(res.succeeded_count, 1);
    assert!(!clean_render.exists(), "stale render.tmp should be deleted");
    assert!(
        keep_proj_file.exists(),
        "case-insensitive exclude `**/Projects/**` MUST protect `PROJECTS/draft.dat`"
    );
    assert!(
        keep_json.exists(),
        "case-insensitive exclude `**/*.json` MUST protect `state.JSON`"
    );

    // 5. Space Lens Cold File Radar MUST filter out ProtectedBlocklist paths (Desktop, Docker.raw, .vhdx)
    fs::create_dir_all(dir.path().join("Desktop")).unwrap();
    fs::create_dir_all(dir.path().join("Library/Containers/com.docker.docker/Data/vms/0/data")).unwrap();
    fs::create_dir_all(dir.path().join("Downloads")).unwrap();
    fs::write(dir.path().join("Desktop/precious.key"), vec![b'K'; 16_384]).unwrap();
    fs::write(
        dir.path().join("Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw"),
        vec![b'V'; 16_384],
    )
    .unwrap();
    fs::write(dir.path().join("Downloads/ext4.vhdx"), vec![b'V'; 16_384]).unwrap();
    fs::write(dir.path().join("Downloads/ArchiveCold.zip"), vec![b'Z'; 16_384]).unwrap();

    let cancel = AtomicBool::new(false);
    let lens = scan_space_lens(dir.path(), 1024, 0, &cancel, |_| {}).unwrap();
    assert!(lens.cold_files.iter().any(|c| c.name == "ArchiveCold.zip"));
    assert!(!lens.cold_files.iter().any(|c| c.name == "precious.key"));
    assert!(!lens.cold_files.iter().any(|c| c.name == "Docker.raw"));
    assert!(!lens.cold_files.iter().any(|c| c.name == "ext4.vhdx"));

    // 6. Authoritative policy prevents callers from downgrading a ReviewRequired+Trash rule to Safe+Permanent
    let old_dmg = dir.path().join("Downloads/ForgedInstaller.dmg");
    fs::write(&old_dmg, vec![b'I'; 16_384]).unwrap();
    let dmg_old = FileTime::from_system_time(SystemTime::now() - Duration::from_secs(90 * 86_400));
    set_file_mtime(&old_dmg, dmg_old).unwrap();

    let downgrade_attempt = execute_clean(
        &[CleanItemRequest {
            rule_id: "system.downloads_old_installers".into(),
            path: old_dmg.clone(),
            risk: RiskLevel::Safe,
            delete_mode: DeleteMode::Permanent,
            native_command: None,
        }],
        false,
    );
    assert_eq!(downgrade_attempt.succeeded_count, 1);
    assert_eq!(
        downgrade_attempt.outcomes[0].actual_mode,
        DeleteMode::Trash,
        "authoritative policy MUST enforce Trash even when caller spoofs RiskLevel::Safe + DeleteMode::Permanent"
    );
    assert!(!old_dmg.exists());
}
