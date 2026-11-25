#![allow(deprecated)]

use clearlens_core::{
    clean_duplicates, clean_orphan_paths, execute_clean, execute_elevation_request,
    load_app_config, run_elevation_worker_files, scan_apps_and_orphans, scan_duplicates,
    scan_space_lens, scan_virtual_disks, uninstall_app_paths, update_ignore_list,
    update_workspace_roots, CleanItemRequest, DeleteMode, DuplicateCleanGroup, ElevationAction,
    ElevationRequest, RiskLevel, TargetPlatform, VirtualDiskKind,
};
use filetime::{set_file_mtime, FileTime};
use std::fs;
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};
use tempfile::tempdir;

static TEST_ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn p0_ollama_refcount_gc_reclaims_only_exclusive_blobs_and_preserves_shared_layers() {
    let _g = TEST_ENV_LOCK.lock().unwrap();
    let dir = tempdir().unwrap();
    std::env::set_var("HOME", dir.path());
    std::env::set_var("XDG_DATA_HOME", dir.path().join(".local/share"));

    let models_dir = dir.path().join(".ollama/models");
    let manifests_dir = models_dir.join("manifests/registry.ollama.ai/library");
    let blobs_dir = models_dir.join("blobs");
    fs::create_dir_all(manifests_dir.join("llama-a")).unwrap();
    fs::create_dir_all(manifests_dir.join("llama-b")).unwrap();
    fs::create_dir_all(&blobs_dir).unwrap();

    let shared_blob = blobs_dir.join("sha256-shared001");
    let blob_a = blobs_dir.join("sha256-modela001");
    let blob_b = blobs_dir.join("sha256-modelb001");
    fs::write(&shared_blob, vec![b'S'; 32_768]).unwrap();
    fs::write(&blob_a, vec![b'A'; 65_536]).unwrap();
    fs::write(&blob_b, vec![b'B'; 49_152]).unwrap();

    let manifest_a = manifests_dir.join("llama-a/latest");
    let manifest_b = manifests_dir.join("llama-b/latest");
    fs::write(
        &manifest_a,
        r#"{"layers":[{"digest":"sha256:shared001"},{"digest":"sha256:modela001"}]}"#,
    )
    .unwrap();
    fs::write(
        &manifest_b,
        r#"{"layers":[{"digest":"sha256:shared001"},{"digest":"sha256:modelb001"}]}"#,
    )
    .unwrap();

    // Remove Model A -> must trash manifest_a & blob_a, while keeping shared_blob & blob_b intact!
    let res_a = execute_clean(
        &[CleanItemRequest {
            rule_id: "ai.ollama_models".into(),
            path: manifest_a.clone(),
            risk: RiskLevel::ReviewRequired,
            delete_mode: DeleteMode::Trash,
            native_command: None,
        }],
        false,
    );
    assert_eq!(res_a.succeeded_count, 1);
    assert!(res_a.total_freed_bytes >= 65_536);
    assert!(!manifest_a.exists());
    assert!(!blob_a.exists());
    assert!(shared_blob.exists(), "shared base layer MUST stay intact while llama-b references it");
    assert!(blob_b.exists());
    assert!(manifest_b.exists());

    // Now remove Model B -> shared_blob refcount drops to 1 and MUST be reclaimed too!
    let res_b = execute_clean(
        &[CleanItemRequest {
            rule_id: "ai.ollama_models".into(),
            path: manifest_b.clone(),
            risk: RiskLevel::ReviewRequired,
            delete_mode: DeleteMode::Trash,
            native_command: None,
        }],
        false,
    );
    assert_eq!(res_b.succeeded_count, 1);
    assert!(res_b.total_freed_bytes >= 32_768 + 49_152);
    assert!(!manifest_b.exists());
    assert!(!blob_b.exists());
    assert!(!shared_blob.exists(), "shared layer should be reclaimed once last referencing model is removed");
}

#[test]
fn p1_blake3_three_stage_duplicates_and_anti_wipe_safety_lock() {
    let _g = TEST_ENV_LOCK.lock().unwrap();
    let dir = tempdir().unwrap();
    std::env::set_var("HOME", dir.path());
    std::env::set_var("XDG_DATA_HOME", dir.path().join(".local/share"));

    let media = dir.path().join("Media");
    let downloads = dir.path().join("Downloads");
    fs::create_dir_all(&media).unwrap();
    fs::create_dir_all(&downloads).unwrap();

    let payload = vec![0x5Au8; 24_576];
    let orig = media.join("movie.mp4");
    let dup1 = downloads.join("movie_copy1.mp4");
    let dup2 = downloads.join("movie_copy2.mp4");
    let hardlink_same = media.join("movie_hardlink.mp4");
    fs::write(&orig, &payload).unwrap();
    fs::write(&dup1, &payload).unwrap();
    fs::write(&dup2, &payload).unwrap();
    fs::hard_link(&orig, &hardlink_same).unwrap();

    // Same exact byte size AND same head/tail 4KB, but different middle byte -> Stage 3 must separate it!
    let mut diff_mid = payload.clone();
    diff_mid[12_000] = 0xFF;
    let distinct = media.join("different_middle.mp4");
    fs::write(&distinct, &diff_mid).unwrap();

    let cancel = AtomicBool::new(false);
    let report = scan_duplicates(&[dir.path().to_path_buf()], 1024, &cancel, |_| {}).unwrap();
    assert_eq!(report.groups.len(), 1, "expected exactly 1 duplicate group");
    assert_eq!(report.skipped_hardlinks, 1, "hardlink sharing same inode must not be flagged as duplicate");

    let grp = &report.groups[0];
    assert_eq!(grp.entries.len(), 3, "only 3 real copies should be in the duplicate group");
    assert!(grp.entries[0].recommended_keep);
    assert_eq!(grp.entries[0].path, orig, "non-Downloads original should be recommended to keep");

    // Anti-wipe lock MUST reject attempting to delete ALL 3 copies
    let all_paths: Vec<_> = grp.entries.iter().map(|e| e.path.clone()).collect();
    let bad_req = vec![DuplicateCleanGroup {
        blake3_hash: grp.blake3_hash.clone(),
        all_paths: all_paths.clone(),
        delete_paths: all_paths.clone(),
    }];
    assert!(
        clean_duplicates(&bad_req, false).is_err(),
        "anti-wipe lock must reject deleting every copy in a duplicate group"
    );

    // Deleting only the 2 non-recommended copies succeeds and routes them to Trash
    let delete_copies: Vec<_> = grp.entries.iter().skip(1).map(|e| e.path.clone()).collect();
    let ok_req = vec![DuplicateCleanGroup {
        blake3_hash: grp.blake3_hash.clone(),
        all_paths,
        delete_paths: delete_copies,
    }];
    let clean_res = clean_duplicates(&ok_req, false).unwrap();
    assert_eq!(clean_res.succeeded_count, 2);
    assert!(orig.exists(), "kept original must remain intact");
    assert!(distinct.exists(), "distinct same-size file must remain intact");
    assert!(!dup1.exists() && !dup2.exists(), "duplicate copies should be moved to Trash");
}

#[test]
fn p1_app_uninstaller_and_orphan_residue_hunter() {
    let _g = TEST_ENV_LOCK.lock().unwrap();
    let dir = tempdir().unwrap();
    std::env::set_var("HOME", dir.path());
    std::env::set_var("XDG_DATA_HOME", dir.path().join(".local/share"));

    let apps_dir = dir.path().join("Applications");
    std::env::set_var("CLEARLENS_APPS_DIR", &apps_dir);

    let keep_app = apps_dir.join("KeepNotes.app/Contents");
    fs::create_dir_all(&keep_app).unwrap();
    fs::write(
        keep_app.join("Info.plist"),
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.example.keepnotes</string>
  <key>CFBundleName</key><string>KeepNotes</string>
</dict></plist>"#,
    )
    .unwrap();
    fs::write(keep_app.join("KeepNotes.bin"), vec![b'K'; 16_384]).unwrap();

    // Residue belonging to installed KeepNotes
    let keep_cache = dir.path().join("Library/Caches/com.example.keepnotes");
    fs::create_dir_all(&keep_cache).unwrap();
    fs::write(keep_cache.join("data.bin"), vec![b'C'; 8192]).unwrap();

    // Protected Apple folder (must NEVER be flagged as orphan)
    let apple_cache = dir.path().join("Library/Caches/com.apple.Safari");
    fs::create_dir_all(&apple_cache).unwrap();
    fs::write(apple_cache.join("cache.db"), vec![b'S'; 8192]).unwrap();

    // Stale orphan folder from a deleted app (40 days old)
    let orphan_dir = dir.path().join("Library/Application Support/com.ghost.deletedapp");
    fs::create_dir_all(&orphan_dir).unwrap();
    let orphan_file = orphan_dir.join("leftover.dat");
    fs::write(&orphan_file, vec![b'G'; 32_768]).unwrap();
    let old_time = FileTime::from_system_time(SystemTime::now() - Duration::from_secs(40 * 86_400));
    set_file_mtime(&orphan_file, old_time).unwrap();
    set_file_mtime(&orphan_dir, old_time).unwrap();

    let cancel = AtomicBool::new(false);
    let report = scan_apps_and_orphans(TargetPlatform::MacOs, 14, &cancel).unwrap();
    std::env::remove_var("CLEARLENS_APPS_DIR");

    assert_eq!(report.apps.len(), 1);
    assert_eq!(report.apps[0].name, "KeepNotes");
    assert!(report.apps[0].residue_bytes >= 8192);

    assert!(
        report.orphans.iter().any(|o| o.path == orphan_dir),
        "deleted app folder should be detected as orphan"
    );
    assert!(
        !report.orphans.iter().any(|o| o.path == apple_cache),
        "system allowlisted com.apple.Safari must NEVER be flagged as orphan"
    );
    assert!(
        !report.orphans.iter().any(|o| o.path == keep_cache),
        "installed app cache must NOT be flagged as orphan"
    );

    let clean_res = clean_orphan_paths(&[orphan_dir.clone()], false);
    assert_eq!(clean_res.succeeded_count, 1);
    assert!(!orphan_dir.exists());
    assert!(keep_cache.exists());
}

#[test]
fn p0_space_lens_deep_drilldown_flag_config_and_elevation_guard() {
    let _g = TEST_ENV_LOCK.lock().unwrap();
    let dir = tempdir().unwrap();
    std::env::set_var("HOME", dir.path());

    // Build a 6-level deep folder to test `has_more_children` at depth 4
    let deep = dir.path().join("a/b/c/d/e/f");
    fs::create_dir_all(&deep).unwrap();
    fs::write(deep.join("payload.bin"), vec![b'P'; 8192]).unwrap();

    let cancel = AtomicBool::new(false);
    let lens = scan_space_lens(dir.path(), 1024, 0, &cancel, |_| {}).unwrap();
    let d_node = &lens.root.children[0].children[0].children[0].children[0];
    assert_eq!(d_node.name, "d");
    assert!(d_node.has_more_children, "depth-4 directory with subdirectories must set has_more_children=true");
    assert!(d_node.children.is_empty());

    // Workspace config persistence
    let ws = dir.path().join("CustomCode");
    fs::create_dir_all(&ws).unwrap();
    let cfg = update_workspace_roots(ws.clone(), false).unwrap();
    assert!(cfg.workspace_roots.contains(&ws));
    assert!(load_app_config().workspace_roots.contains(&ws));
    let cfg2 = update_workspace_roots(ws.clone(), true).unwrap();
    assert!(!cfg2.workspace_roots.contains(&ws));

    // Elevated worker must STILL enforce ProtectedBlocklist
    let bad_elev = ElevationRequest {
        request_id: "req-1".into(),
        action: ElevationAction::CleanElevatedPaths {
            items: vec![CleanItemRequest {
                rule_id: "elev.test".into(),
                path: dir.path().join(".ssh/id_rsa"),
                risk: RiskLevel::Safe,
                delete_mode: DeleteMode::Permanent,
                native_command: None,
            }],
            dry_run: false,
        },
    };
    let elev_res = execute_elevation_request(&bad_elev);
    assert!(!elev_res.success, "elevated worker MUST still block protected paths like ~/.ssh");
}

#[test]
fn vdisk_windows_wsl2_and_docker_vhdx_detection_and_compact_script() {
    let _g = TEST_ENV_LOCK.lock().unwrap();
    let dir = tempdir().unwrap();
    let local_appdata = dir.path().join("AppData/Local");
    std::env::set_var("HOME", dir.path());
    std::env::set_var("LOCALAPPDATA", &local_appdata);

    let ubuntu_dir = local_appdata
        .join("Packages/CanonicalGroupLimited.Ubuntu_79rhkp1fndgsc/LocalState");
    let docker_dir = local_appdata.join("Docker/wsl/disk");
    fs::create_dir_all(&ubuntu_dir).unwrap();
    fs::create_dir_all(&docker_dir).unwrap();

    let wsl_vhdx = ubuntu_dir.join("ext4.vhdx");
    let docker_vhdx = docker_dir.join("docker_data.vhdx");
    fs::write(&wsl_vhdx, vec![0x11u8; 65_536]).unwrap();
    fs::write(&docker_vhdx, vec![0x22u8; 131_072]).unwrap();

    let report = scan_virtual_disks(TargetPlatform::Windows);
    std::env::remove_var("LOCALAPPDATA");

    assert_eq!(report.disks.len(), 2, "expected both WSL2 and Docker Desktop VHDX entries");
    let docker = report
        .disks
        .iter()
        .find(|d| d.kind == VirtualDiskKind::DockerDesktopVhdx)
        .expect("Docker Desktop VHDX should be detected");
    let wsl = report
        .disks
        .iter()
        .find(|d| d.kind == VirtualDiskKind::Wsl2Vhdx)
        .expect("WSL2 distro ext4.vhdx should be detected");

    assert!(docker.compact_script.contains("wsl --shutdown"));
    assert!(docker.compact_script.contains("Optimize-VHD"));
    assert!(docker.compact_script.contains("compact vdisk"));
    assert!(wsl.name.contains("CanonicalGroupLimited.Ubuntu"));
    assert!(wsl.requires_elevation);
    // Inspector must NEVER delete virtual disk images!
    assert!(wsl_vhdx.exists() && docker_vhdx.exists());
}

#[test]
fn vdisk_macos_sparse_docker_raw_distinguishes_physical_vs_logical() {
    let _g = TEST_ENV_LOCK.lock().unwrap();
    let dir = tempdir().unwrap();
    std::env::set_var("HOME", dir.path());

    let vm_dir = dir
        .path()
        .join("Library/Containers/com.docker.docker/Data/vms/0/data");
    fs::create_dir_all(&vm_dir).unwrap();
    let docker_raw = vm_dir.join("Docker.raw");

    {
        use std::io::Write;
        let mut f = fs::File::create(&docker_raw).unwrap();
        f.write_all(&vec![0xABu8; 65_536]).unwrap();
        f.set_len(16 * 1024 * 1024).unwrap();
        f.sync_all().unwrap();
    }

    let report = scan_virtual_disks(TargetPlatform::MacOs);
    assert_eq!(report.disks.len(), 1);
    let d = &report.disks[0];
    assert_eq!(d.kind, VirtualDiskKind::DockerDesktopRawMac);
    assert_eq!(d.logical_bytes, 16 * 1024 * 1024);
    assert!(
        d.allocated_bytes <= d.logical_bytes,
        "physical allocation ({}) must never exceed logical ceiling ({})",
        d.allocated_bytes,
        d.logical_bytes
    );
    #[cfg(unix)]
    {
        assert!(
            d.allocated_bytes < d.logical_bytes,
            "sparse Docker.raw physical allocation ({}) should be less than logical ceiling ({})",
            d.allocated_bytes,
            d.logical_bytes
        );
        assert!(d.sparse_savings_bytes > 0);
    }
    assert!(d.compact_command.contains("docker builder prune"));
    assert!(docker_raw.exists());
}

#[test]
fn code_review_regressions_ollama_traversal_trash_collisions_tilde_and_ps_quoting() {
    let _g = TEST_ENV_LOCK.lock().unwrap();
    let dir = tempdir().unwrap();
    std::env::set_var("HOME", dir.path());
    let xdg = dir.path().join(".local/share");
    std::env::set_var("XDG_DATA_HOME", &xdg);

    // 1. Ollama manifest with malicious `../../outside_secret` digest MUST NOT traverse outside blobs/
    let outside_secret = dir.path().join("outside_secret");
    fs::write(&outside_secret, vec![b'S'; 8192]).unwrap();
    let models_dir = dir.path().join(".ollama/models");
    let manifest_dir = models_dir.join("manifests/registry.ollama.ai/library/evil");
    let blobs_dir = models_dir.join("blobs");
    fs::create_dir_all(&manifest_dir).unwrap();
    fs::create_dir_all(&blobs_dir).unwrap();
    let ok_blob = blobs_dir.join("sha256-goodlayer01");
    fs::write(&ok_blob, vec![b'G'; 16_384]).unwrap();
    let evil_manifest = manifest_dir.join("latest");
    fs::write(
        &evil_manifest,
        r#"{"config":{"digest":"../../outside_secret"},"layers":[{"digest":"sha256:../../outside_secret"},{"digest":"sha256:goodlayer01"}]}"#,
    )
    .unwrap();

    let gc_res = execute_clean(
        &[CleanItemRequest {
            rule_id: "ai.ollama_models".into(),
            path: evil_manifest,
            risk: RiskLevel::ReviewRequired,
            delete_mode: DeleteMode::Trash,
            native_command: None,
        }],
        false,
    );
    assert_eq!(gc_res.succeeded_count, 1);
    assert!(!ok_blob.exists(), "legitimate exclusive blob should be trashed");
    assert!(
        outside_secret.exists(),
        "malicious traversal digest MUST NEVER touch files outside blobs/"
    );

    // 2. Moving 4 identically-named files to Trash within the same millisecond MUST NOT overwrite any copy
    let mut same_name_reqs = Vec::new();
    for idx in 0..4 {
        let sub = dir.path().join(format!("dup_dir_{idx}"));
        fs::create_dir_all(&sub).unwrap();
        let f = sub.join("identical_name.mp4");
        fs::write(&f, format!("COPY_PAYLOAD_{idx}").as_bytes()).unwrap();
        same_name_reqs.push(CleanItemRequest {
            rule_id: "test.trash_collision".into(),
            path: f,
            risk: RiskLevel::ReviewRequired,
            delete_mode: DeleteMode::Trash,
            native_command: None,
        });
    }
    let tr_res = execute_clean(&same_name_reqs, false);
    assert_eq!(tr_res.succeeded_count, 4);
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let trashed_count = fs::read_dir(xdg.join("Trash/files"))
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("identical_name.mp4"))
            .count();
        assert_eq!(
            trashed_count, 4,
            "all 4 same-millisecond identically-named trashed files must survive without overwriting"
        );
    }

    // 3. `~/` workspace root expansion in config
    let tilde_cfg = update_workspace_roots(std::path::PathBuf::from("~/TildeProjects"), false).unwrap();
    assert!(
        tilde_cfg
            .workspace_roots
            .contains(&dir.path().join("TildeProjects")),
        "`~/TildeProjects` must expand `~` to HOME when saved in config"
    );

    // 4. PowerShell single-quote literal escaping when VHDX path contains `$`
    let dollar_local = dir.path().join("AppData/Local");
    std::env::set_var("LOCALAPPDATA", &dollar_local);
    let tricky_pkg = dollar_local.join("Packages/Distro$EnvTest_abc/LocalState");
    fs::create_dir_all(&tricky_pkg).unwrap();
    fs::write(tricky_pkg.join("ext4.vhdx"), vec![0x33u8; 16_384]).unwrap();
    let vrep = scan_virtual_disks(TargetPlatform::Windows);
    std::env::remove_var("LOCALAPPDATA");
    assert_eq!(vrep.disks.len(), 1);
    assert!(
        vrep.disks[0].compact_script.contains("$vhdx = '"),
        "PowerShell $vhdx assignment must use single-quoted literal to prevent $-expansion"
    );
}

#[test]
fn pass3_elevated_scope_ollama_spoof_duplicate_toctou_and_uninstaller_scope() {
    let _g = TEST_ENV_LOCK.lock().unwrap();
    let dir = tempdir().unwrap();
    std::env::set_var("HOME", dir.path());
    let xdg = dir.path().join(".local/share");
    std::env::set_var("XDG_DATA_HOME", &xdg);

    // 1. Elevated worker MUST reject non-elevated rules AND out-of-scope paths for elevated rules
    let fake_windir = dir.path().join("FakeWindows");
    let win_update_dl = fake_windir.join("SoftwareDistribution/Download");
    fs::create_dir_all(&win_update_dl).unwrap();
    let old_cab = win_update_dl.join("pkg.cab");
    fs::write(&old_cab, vec![b'U'; 8192]).unwrap();
    let cab_old_time =
        FileTime::from_system_time(SystemTime::now() - Duration::from_secs(20 * 86_400));
    set_file_mtime(&old_cab, cab_old_time).unwrap();
    let outside_elev = dir.path().join("Outside/secret.dat");
    fs::create_dir_all(outside_elev.parent().unwrap()).unwrap();
    fs::write(&outside_elev, b"KEEP").unwrap();
    std::env::set_var("WINDIR", &fake_windir);

    let non_elev_rule = ElevationRequest {
        request_id: "elev-non".into(),
        action: ElevationAction::CleanElevatedPaths {
            items: vec![CleanItemRequest {
                rule_id: "system.temp_files".into(),
                path: outside_elev.clone(),
                risk: RiskLevel::Safe,
                delete_mode: DeleteMode::Permanent,
                native_command: None,
            }],
            dry_run: true,
        },
    };
    assert!(
        !execute_elevation_request(&non_elev_rule).success,
        "elevated worker MUST reject non-elevated rules like system.temp_files"
    );

    let out_of_scope_elev = ElevationRequest {
        request_id: "elev-oos".into(),
        action: ElevationAction::CleanElevatedPaths {
            items: vec![CleanItemRequest {
                rule_id: "system.windows_update_cache".into(),
                path: outside_elev.clone(),
                risk: RiskLevel::Recreatable,
                delete_mode: DeleteMode::Permanent,
                native_command: None,
            }],
            dry_run: false,
        },
    };
    assert!(
        !execute_elevation_request(&out_of_scope_elev).success,
        "elevated worker MUST reject paths outside rule anchor_dirs"
    );
    assert!(outside_elev.exists());

    let in_scope_elev = ElevationRequest {
        request_id: "elev-ok".into(),
        action: ElevationAction::CleanElevatedPaths {
            items: vec![CleanItemRequest {
                rule_id: "system.windows_update_cache".into(),
                path: win_update_dl.join("pkg.cab"),
                risk: RiskLevel::Recreatable,
                delete_mode: DeleteMode::Permanent,
                native_command: None,
            }],
            dry_run: true,
        },
    };
    assert!(execute_elevation_request(&in_scope_elev).success);
    std::env::remove_var("WINDIR");

    // Symbolic link protection on elevated worker file transport
    #[cfg(unix)]
    {
        let req_real = dir.path().join("req.json");
        let resp_target = dir.path().join("clobber_target.txt");
        fs::write(&req_real, "{}").unwrap();
        fs::write(&resp_target, "DO_NOT_OVERWRITE").unwrap();
        let symlink_req = dir.path().join("req_link.json");
        let symlink_resp = dir.path().join("resp_link.json");
        std::os::unix::fs::symlink(&req_real, &symlink_req).unwrap();
        std::os::unix::fs::symlink(&resp_target, &symlink_resp).unwrap();
        assert!(run_elevation_worker_files(&symlink_req, &dir.path().join("out.json")).is_err());
        assert!(run_elevation_worker_files(&req_real, &symlink_resp).is_err());
        assert_eq!(fs::read_to_string(&resp_target).unwrap(), "DO_NOT_OVERWRITE");
    }

    // 2. Spoofed `ai.ollama_models` pointing outside `.ollama/models` MUST be rejected, and ignore_paths respected
    let fake_manifest = dir.path().join("Projects/k8s-app/manifests/v1/config.json");
    fs::create_dir_all(fake_manifest.parent().unwrap()).unwrap();
    fs::write(&fake_manifest, r#"{"layers":[{"digest":"sha256:abc"}]}"#).unwrap();
    let spoof_ollama = execute_clean(
        &[CleanItemRequest {
            rule_id: "ai.ollama_models".into(),
            path: fake_manifest.clone(),
            risk: RiskLevel::ReviewRequired,
            delete_mode: DeleteMode::Trash,
            native_command: None,
        }],
        false,
    );
    assert_eq!(spoof_ollama.failed_count, 1);
    assert!(fake_manifest.exists(), "non-Ollama manifest MUST NOT be trashed");

    let real_ollama_dir = dir.path().join(".ollama/models");
    let real_manifest = real_ollama_dir.join("manifests/registry.ollama.ai/library/keepme/latest");
    let real_blobs = real_ollama_dir.join("blobs");
    fs::create_dir_all(real_manifest.parent().unwrap()).unwrap();
    fs::create_dir_all(&real_blobs).unwrap();
    let real_blob = real_blobs.join("sha256-ignoredblob1");
    fs::write(&real_blob, vec![b'O'; 8192]).unwrap();
    fs::write(&real_manifest, r#"{"layers":[{"digest":"sha256:ignoredblob1"}]}"#).unwrap();
    update_ignore_list(real_manifest.clone(), false).unwrap();
    let ignored_ollama = execute_clean(
        &[CleanItemRequest {
            rule_id: "ai.ollama_models".into(),
            path: real_manifest.clone(),
            risk: RiskLevel::ReviewRequired,
            delete_mode: DeleteMode::Trash,
            native_command: None,
        }],
        false,
    );
    assert_eq!(ignored_ollama.failed_count, 1);
    assert!(real_manifest.exists() && real_blob.exists());
    let _ = update_ignore_list(real_manifest, true);

    // 3. Duplicate Anti-Wipe TOCTOU: if the survivor copy changes after scan, clean_duplicates MUST abort
    let dup_dir = dir.path().join("DupToctou");
    fs::create_dir_all(&dup_dir).unwrap();
    let keep_file = dup_dir.join("keep_a.bin");
    let del_file = dup_dir.join("copy_b.bin");
    fs::write(&keep_file, vec![0x7Au8; 16_384]).unwrap();
    fs::write(&del_file, vec![0x7Au8; 16_384]).unwrap();
    let cancel = AtomicBool::new(false);
    let drep = scan_duplicates(&[dup_dir], 1024, &cancel, |_| {}).unwrap();
    assert_eq!(drep.groups.len(), 1);
    let grp = &drep.groups[0];
    let survivor_path = &grp.entries[0].path;
    let copy_path = &grp.entries[1].path;
    // Simulate post-scan mutation/truncation of survivor before cleaning
    fs::write(survivor_path, vec![0xFFu8; 4096]).unwrap();
    let toctou_err = clean_duplicates(
        &[DuplicateCleanGroup {
            blake3_hash: grp.blake3_hash.clone(),
            all_paths: vec![survivor_path.clone(), copy_path.clone()],
            delete_paths: vec![copy_path.clone()],
        }],
        false,
    );
    assert!(
        toctou_err.is_err(),
        "anti-wipe TOCTOU check MUST abort when surviving copy hash changed after scan"
    );
    assert!(copy_path.exists(), "intact copy MUST survive TOCTOU mismatch");

    // 4. Uninstaller scope & ClearLens self-protection
    let dl_keep = dir.path().join("Downloads/keep_installer.zip");
    fs::create_dir_all(dl_keep.parent().unwrap()).unwrap();
    fs::write(&dl_keep, b"DO_NOT_DELETE").unwrap();
    let self_res = uninstall_app_paths("ClearLens", &[dl_keep.clone()], false);
    assert_eq!(self_res.succeeded_count, 0);
    assert!(dl_keep.exists());

    let oos_orphan = clean_orphan_paths(&[dl_keep.clone()], false);
    assert_eq!(oos_orphan.succeeded_count, 0);
    assert_eq!(oos_orphan.failed_count, 1);
    assert!(
        dl_keep.exists(),
        "clean_orphan_paths MUST reject user paths outside residue directories"
    );
}
