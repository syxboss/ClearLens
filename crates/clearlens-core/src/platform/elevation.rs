use crate::cleaner::execute_clean;
use crate::models::{
    CleanItemRequest, CleanReport, ElevationAction, ElevationRequest, ElevationResult,
};
use crate::platform::thin_local_snapshots;
use crate::safety::{is_metadata_reparse_or_symlink, ProtectedBlocklist};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::Command;

/// Executes an on-demand elevated worker request while strictly enforcing ClearLens's
/// engine-hardcoded ProtectedBlocklist and compile-time embedded elevation rule scopes.
pub fn execute_elevation_request(req: &ElevationRequest) -> ElevationResult {
    match &req.action {
        ElevationAction::CleanElevatedPaths { items, dry_run } => {
            let builtin_elev = crate::rules::build_builtin_elevation_policies();
            for item in items {
                if let Err(err) = ProtectedBlocklist::check_path(&item.path) {
                    return ElevationResult {
                        request_id: req.request_id.clone(),
                        success: false,
                        message: format!("elevated worker rejected protected path: {err}"),
                        clean_report: None,
                    };
                }
                let Some(policy) = builtin_elev.get(&item.rule_id) else {
                    return ElevationResult {
                        request_id: req.request_id.clone(),
                        success: false,
                        message: format!(
                            "elevated worker rejected rule '{}' (only built-in requires_elevation rules are permitted)",
                            item.rule_id
                        ),
                        clean_report: None,
                    };
                };
                if !item.path.is_absolute() {
                    return ElevationResult {
                        request_id: req.request_id.clone(),
                        success: false,
                        message: format!(
                            "elevated worker rejected non-absolute target path: {}",
                            item.path.display()
                        ),
                        clean_report: None,
                    };
                }
                let in_scope = !policy.anchor_dirs.is_empty()
                    && policy.anchor_dirs.iter().any(|anchor| {
                        anchor.is_absolute()
                            && crate::config::path_starts_with_for_policy(&item.path, anchor)
                    });
                if !in_scope {
                    return ElevationResult {
                        request_id: req.request_id.clone(),
                        success: false,
                        message: format!(
                            "elevated worker rejected out-of-scope path '{}' for rule '{}'",
                            item.path.display(),
                            item.rule_id
                        ),
                        clean_report: None,
                    };
                }
            }
            let report = execute_clean(items, *dry_run);
            let ok = report.failed_count == 0;
            ElevationResult {
                request_id: req.request_id.clone(),
                success: ok,
                message: format!(
                    "elevated cleanup finished: {} succeeded, {} failed, freed {} bytes",
                    report.succeeded_count, report.failed_count, report.total_freed_bytes
                ),
                clean_report: Some(report),
            }
        }
        ElevationAction::MacOsThinSnapshots {
            bytes_to_free,
            dry_run,
        } => match thin_local_snapshots(*bytes_to_free, *dry_run) {
            Ok(msg) => ElevationResult {
                request_id: req.request_id.clone(),
                success: true,
                message: msg,
                clean_report: None,
            },
            Err(err) => ElevationResult {
                request_id: req.request_id.clone(),
                success: false,
                message: err,
                clean_report: None,
            },
        },
        ElevationAction::WindowsDismCleanup { dry_run } => {
            if *dry_run {
                return ElevationResult {
                    request_id: req.request_id.clone(),
                    success: true,
                    message: "[dry-run] DISM.exe /Online /Cleanup-Image /StartComponentCleanup"
                        .to_string(),
                    clean_report: None,
                };
            }
            #[cfg(windows)]
            {
                let out = Command::new("DISM.exe")
                    .args(["/Online", "/Cleanup-Image", "/StartComponentCleanup"])
                    .output();
                match out {
                    Ok(o) if o.status.success() => ElevationResult {
                        request_id: req.request_id.clone(),
                        success: true,
                        message: String::from_utf8_lossy(&o.stdout).trim().to_string(),
                        clean_report: None,
                    },
                    Ok(o) => ElevationResult {
                        request_id: req.request_id.clone(),
                        success: false,
                        message: String::from_utf8_lossy(&o.stderr).trim().to_string(),
                        clean_report: None,
                    },
                    Err(e) => ElevationResult {
                        request_id: req.request_id.clone(),
                        success: false,
                        message: e.to_string(),
                        clean_report: None,
                    },
                }
            }
            #[cfg(not(windows))]
            {
                let _ = Command::new("true");
                ElevationResult {
                    request_id: req.request_id.clone(),
                    success: false,
                    message: "DISM component cleanup is only available on Windows".to_string(),
                    clean_report: None,
                }
            }
        }
    }
}

/// File-based worker entry point invoked by `clens elevated-worker --request <in> --response <out>`.
pub fn run_elevation_worker_files(req_path: &Path, resp_path: &Path) -> Result<ElevationResult, String> {
    std::env::set_var("CLEARLENS_IN_ELEVATED_WORKER", "1");
    let req_meta = fs::symlink_metadata(req_path)
        .map_err(|e| format!("failed to stat elevation request {}: {e}", req_path.display()))?;
    if is_metadata_reparse_or_symlink(&req_meta) || !req_meta.is_file() {
        return Err(format!(
            "refusing non-regular or symlinked elevation request: {}",
            req_path.display()
        ));
    }
    if fs::symlink_metadata(resp_path).is_ok() {
        return Err(format!(
            "refusing to overwrite pre-existing or symlinked elevation response: {}",
            resp_path.display()
        ));
    }

    let raw = fs::read_to_string(req_path)
        .map_err(|e| format!("failed to read elevation request {}: {e}", req_path.display()))?;
    let req: ElevationRequest =
        serde_json::from_str(&raw).map_err(|e| format!("invalid elevation request JSON: {e}"))?;
    let res = execute_elevation_request(&req);
    let out = serde_json::to_string_pretty(&res).map_err(|e| e.to_string())?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(resp_path)
        .map_err(|e| format!("failed to create elevation response {}: {e}", resp_path.display()))?;
    f.write_all(out.as_bytes())
        .map_err(|e| format!("failed to write elevation response {}: {e}", resp_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Response lives inside the caller's 0700 tempdir; make readable by caller even if root umask is 0077.
        let _ = fs::set_permissions(resp_path, fs::Permissions::from_mode(0o644));
    }
    Ok(res)
}

/// Spawns a one-shot elevated worker using the current executable (`elevated-worker`) to retry
/// permission-denied cleanup items on demand, reading back the serialized `ElevationResult`.
pub fn invoke_elevated_clean(items: &[CleanItemRequest], dry_run: bool) -> Result<CleanReport, String> {
    if std::env::var_os("CLEARLENS_IN_ELEVATED_WORKER").is_some() {
        return Err("already inside elevated worker".to_string());
    }
    let dir = tempfile::Builder::new()
        .prefix("clearlens-elev-")
        .tempdir()
        .map_err(|e| format!("failed to create elevation staging dir: {e}"))?;
    let req_path = dir.path().join("request.json");
    let resp_path = dir.path().join("response.json");

    let req = ElevationRequest {
        request_id: format!("elev-{}", std::process::id()),
        action: ElevationAction::CleanElevatedPaths {
            items: items.to_vec(),
            dry_run,
        },
    };
    let req_json = serde_json::to_string_pretty(&req).map_err(|e| e.to_string())?;
    fs::write(&req_path, req_json).map_err(|e| format!("failed to stage elevation request: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&req_path, fs::Permissions::from_mode(0o600));
    }

    let exe = std::env::current_exe()
        .map_err(|e| format!("failed to resolve current executable for elevation: {e}"))?;
    launch_elevated_worker(&exe, &req_path, &resp_path)?;

    let resp_raw = fs::read_to_string(&resp_path)
        .map_err(|e| format!("failed to read elevation response: {e}"))?;
    let res: ElevationResult = serde_json::from_str(&resp_raw)
        .map_err(|e| format!("invalid elevation response JSON: {e}"))?;
    res.clean_report.ok_or(res.message)
}

/// Launches a one-shot elevated child process (`ShellExecuteExW("runas")` + wait on Windows,
/// `osascript` admin prompt on macOS, `pkexec` on Linux) and waits until it writes `resp_path`.
#[cfg(windows)]
pub fn launch_elevated_worker(exe: &Path, req_path: &Path, resp_path: &Path) -> Result<(), String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::WaitForSingleObject;
    use windows_sys::Win32::UI::Shell::{
        ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let verb: Vec<u16> = OsStr::new("runas").encode_wide().chain(Some(0)).collect();
    let file: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
    let req_clean = req_path.to_string_lossy().replace('"', "");
    let resp_clean = resp_path.to_string_lossy().replace('"', "");
    let params_str = format!("elevated-worker --request \"{req_clean}\" --response \"{resp_clean}\"");
    let params: Vec<u16> = OsStr::new(&params_str)
        .encode_wide()
        .chain(Some(0))
        .collect();

    unsafe {
        let mut sei: SHELLEXECUTEINFOW = std::mem::zeroed();
        sei.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.lpVerb = verb.as_ptr();
        sei.lpFile = file.as_ptr();
        sei.lpParameters = params.as_ptr();
        sei.nShow = SW_HIDE;

        if ShellExecuteExW(&mut sei) == 0 {
            return Err("UAC elevation canceled or ShellExecuteExW failed".to_string());
        }
        if !sei.hProcess.is_null() {
            WaitForSingleObject(sei.hProcess, 300_000);
            CloseHandle(sei.hProcess);
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn launch_elevated_worker(exe: &Path, req_path: &Path, resp_path: &Path) -> Result<(), String> {
    let sh_quote = |p: &Path| format!("'{}'", p.to_string_lossy().replace('\'', "'\\''"));
    let shell_cmd = format!(
        "{} elevated-worker --request {} --response {}",
        sh_quote(exe),
        sh_quote(req_path),
        sh_quote(resp_path)
    );
    let apple_escaped = shell_cmd.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!("do shell script \"{apple_escaped}\" with administrator privileges");
    let out = Command::new("osascript")
        .args(["-e", &script])
        .output()
        .map_err(|e| format!("failed to launch osascript: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn launch_elevated_worker(exe: &Path, req_path: &Path, resp_path: &Path) -> Result<(), String> {
    let out = Command::new("pkexec")
        .arg(exe)
        .arg("elevated-worker")
        .arg("--request")
        .arg(req_path)
        .arg("--response")
        .arg(resp_path)
        .output()
        .map_err(|e| format!("failed to invoke pkexec: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}
