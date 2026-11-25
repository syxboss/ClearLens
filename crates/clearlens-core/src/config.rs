use crate::models::{AppConfig, TargetPlatform};
use crate::platform::resolve_home_dir;
use crate::rules::expand_env_vars;
use crate::safety::is_metadata_reparse_or_symlink;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn config_path() -> PathBuf {
    resolve_home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".clearlens")
        .join("config.json")
}

/// Expands leading `~`, `$HOME`, and `%VAR%` tokens in user-supplied paths and trims redundant trailing slashes.
pub fn normalize_user_path(raw: &Path) -> PathBuf {
    let raw_str = raw.to_string_lossy();
    let trimmed = raw_str.trim();
    if trimmed.is_empty() {
        return PathBuf::new();
    }
    let expanded = expand_env_vars(trimmed, TargetPlatform::current())
        .unwrap_or_else(|| trimmed.to_string());
    if expanded.len() > 1 && !expanded.ends_with(":/") && !expanded.ends_with(":\\") {
        PathBuf::from(expanded.trim_end_matches(['/', '\\']))
    } else {
        PathBuf::from(expanded)
    }
}

pub fn load_app_config() -> AppConfig {
    let path = config_path();
    let Ok(raw) = fs::read_to_string(path) else {
        return AppConfig::default();
    };
    let mut cfg: AppConfig = serde_json::from_str(&raw).unwrap_or_default();
    cfg.ignore_paths = cfg
        .ignore_paths
        .into_iter()
        .map(|p| normalize_user_path(&p))
        .filter(|p| !p.as_os_str().is_empty())
        .collect();
    cfg.workspace_roots = cfg
        .workspace_roots
        .into_iter()
        .map(|p| normalize_user_path(&p))
        .filter(|p| !p.as_os_str().is_empty())
        .collect();
    cfg
}

pub fn save_app_config(cfg: &AppConfig) -> std::io::Result<()> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    if let Ok(meta) = fs::symlink_metadata(&path) {
        if is_metadata_reparse_or_symlink(&meta) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "refusing to write config through symlink",
            ));
        }
    }

    let json = serde_json::to_string_pretty(cfg).map_err(|e| std::io::Error::other(e.to_string()))?;
    let tmp_path = path.with_extension(format!("json.tmp.{}", std::process::id()));
    let _ = fs::remove_file(&tmp_path);
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        set_private_file_mode(&tmp_path);
        f.write_all(json.as_bytes())?;
    }
    if let Err(_rename_err) = fs::rename(&tmp_path, &path) {
        let _ = fs::remove_file(&tmp_path);
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if is_metadata_reparse_or_symlink(&meta) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "refusing to write config through symlink",
                ));
            }
        }
        fs::write(&path, &json)?;
    }
    set_private_file_mode(&path);
    Ok(())
}

pub(crate) fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    if let Ok(meta) = fs::symlink_metadata(dir) {
        if is_metadata_reparse_or_symlink(&meta) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "refusing to use symlinked state directory",
            ));
        }
    } else {
        fs::create_dir_all(dir)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

pub(crate) fn set_private_file_mode(file: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(file, fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = file;
}

pub fn update_ignore_list(target: PathBuf, remove: bool) -> std::io::Result<AppConfig> {
    let norm = normalize_user_path(&target);
    let mut cfg = load_app_config();
    if remove {
        cfg.ignore_paths
            .retain(|p| !paths_equal_for_policy(p, &norm) && !paths_equal_for_policy(p, &target));
    } else if !norm.as_os_str().is_empty()
        && !cfg.ignore_paths.iter().any(|p| paths_equal_for_policy(p, &norm))
    {
        cfg.ignore_paths.push(norm);
    }
    save_app_config(&cfg)?;
    Ok(cfg)
}

pub fn update_workspace_roots(target: PathBuf, remove: bool) -> std::io::Result<AppConfig> {
    let norm = normalize_user_path(&target);
    let mut cfg = load_app_config();
    if remove {
        cfg.workspace_roots
            .retain(|p| !paths_equal_for_policy(p, &norm) && !paths_equal_for_policy(p, &target));
    } else if !norm.as_os_str().is_empty()
        && !cfg
            .workspace_roots
            .iter()
            .any(|p| paths_equal_for_policy(p, &norm))
    {
        cfg.workspace_roots.push(norm);
    }
    save_app_config(&cfg)?;
    Ok(cfg)
}

pub fn update_default_stale_days(days: u32) -> std::io::Result<AppConfig> {
    let mut cfg = load_app_config();
    cfg.default_stale_days = days.max(1);
    save_app_config(&cfg)?;
    Ok(cfg)
}

pub fn is_path_ignored(path: &Path, ignore_paths: &[PathBuf]) -> bool {
    ignore_paths
        .iter()
        .any(|ig| !ig.as_os_str().is_empty() && path_starts_with_for_policy(path, ig))
}

pub fn dir_contains_ignored(dir: &Path, ignore_paths: &[PathBuf]) -> bool {
    ignore_paths.iter().any(|ig| {
        !ig.as_os_str().is_empty()
            && path_starts_with_for_policy(ig, dir)
            && !paths_equal_for_policy(ig, dir)
    })
}

pub fn path_starts_with_for_policy(path: &Path, prefix: &Path) -> bool {
    let ci = cfg!(any(target_os = "macos", windows));
    if path_starts_with_normalized(path, prefix, ci) {
        return true;
    }
    if path.exists() && prefix.exists() {
        if let (Ok(cp), Ok(cg)) = (fs::canonicalize(path), fs::canonicalize(prefix)) {
            return path_starts_with_normalized(&cp, &cg, ci);
        }
    }
    false
}

pub fn paths_equal_for_policy(a: &Path, b: &Path) -> bool {
    let ci = cfg!(any(target_os = "macos", windows));
    if paths_equal_normalized(a, b, ci) {
        return true;
    }
    if a.exists() && b.exists() {
        if let (Ok(ca), Ok(cb)) = (fs::canonicalize(a), fs::canonicalize(b)) {
            return paths_equal_normalized(&ca, &cb, ci);
        }
    }
    false
}

pub fn path_starts_with_normalized(path: &Path, prefix: &Path, case_insensitive: bool) -> bool {
    let Some(p_segs) = normalize_policy_segments(path) else {
        return false;
    };
    let Some(g_segs) = normalize_policy_segments(prefix) else {
        return false;
    };
    if g_segs.is_empty() || p_segs.len() < g_segs.len() {
        return false;
    }
    g_segs.iter().zip(p_segs.iter()).all(|(g, p)| {
        if case_insensitive {
            g.eq_ignore_ascii_case(p)
        } else {
            g == p
        }
    })
}

pub fn paths_equal_normalized(a: &Path, b: &Path, case_insensitive: bool) -> bool {
    let Some(a_segs) = normalize_policy_segments(a) else {
        return false;
    };
    let Some(b_segs) = normalize_policy_segments(b) else {
        return false;
    };
    if a_segs.is_empty() || a_segs.len() != b_segs.len() {
        return false;
    }
    a_segs.iter().zip(b_segs.iter()).all(|(x, y)| {
        if case_insensitive {
            x.eq_ignore_ascii_case(y)
        } else {
            x == y
        }
    })
}

fn normalize_policy_segments(path: &Path) -> Option<Vec<String>> {
    let raw = path.to_string_lossy();
    let trimmed_raw = raw.trim();
    if trimmed_raw.is_empty() {
        return None;
    }
    let slashes = trimmed_raw.replace('\\', "/");
    let lower = slashes.to_ascii_lowercase();
    let unprefixed = if lower.starts_with("//?/unc/") {
        format!("/{}", &slashes["//?/unc/".len()..])
    } else if lower.starts_with("//?/") || lower.starts_with("//./") {
        slashes[4..].to_string()
    } else {
        slashes
    };

    let mut collapsed = String::with_capacity(unprefixed.len());
    let mut prev_slash = false;
    for ch in unprefixed.chars() {
        if ch == '/' {
            if !prev_slash {
                collapsed.push('/');
            }
            prev_slash = true;
        } else {
            prev_slash = false;
            collapsed.push(ch);
        }
    }

    let cleaned = if collapsed.len() > 1 {
        collapsed.trim_end_matches('/').to_string()
    } else {
        collapsed
    };
    if cleaned.is_empty() {
        return None;
    }

    // Normalize macOS root symlink prefixes `/private/{var,tmp,etc}` -> `/{var,tmp,etc}`
    let clower = cleaned.to_ascii_lowercase();
    let canonical_root_alias = if let Some(rest) = clower.strip_prefix("/private/") {
        if matches!(rest, "var" | "tmp" | "etc")
            || rest.starts_with("var/")
            || rest.starts_with("tmp/")
            || rest.starts_with("etc/")
        {
            format!("/{}", &cleaned["/private/".len()..])
        } else {
            cleaned
        }
    } else {
        cleaned
    };

    let mut segs = Vec::new();
    if canonical_root_alias == "/" {
        segs.push("/".to_string());
        return Some(segs);
    }
    if canonical_root_alias.starts_with('/') {
        segs.push("/".to_string());
    }
    for (idx, part) in canonical_root_alias
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .enumerate()
    {
        if part == ".." {
            return None;
        }
        if idx == 0 && part.len() == 2 && part.as_bytes()[0].is_ascii_alphabetic() && part.as_bytes()[1] == b':' {
            segs.push(part.to_ascii_lowercase());
        } else {
            segs.push(part.to_string());
        }
    }

    if segs.is_empty() {
        None
    } else {
        Some(segs)
    }
}
