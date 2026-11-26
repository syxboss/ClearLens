use crate::models::RuleFile;
use crate::platform::{inspect_path_meta, resolve_home_dir};
use rustc_hash::FxHashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use sysinfo::{ProcessRefreshKind, RefreshKind, System};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SafetyError {
    #[error("protected path blocked by ClearLens safety guardrail: {0}")]
    ProtectedPath(String),
    #[error("unsafe rule glob pattern rejected: {0}")]
    UnsafeRulePattern(String),
    #[error("symlink or reparse point cannot be traversed or deleted through: {0}")]
    SymlinkBlocked(String),
}

pub struct ProtectedBlocklist;

impl ProtectedBlocklist {
    /// Checks whether a concrete filesystem path is protected by engine-hardcoded safety guardrails.
    /// Rejects `..` traversal segments, ancestor symlinks/reparse points (beyond OS root links like
    /// `/var` or `/tmp`), Windows verbatim (`\\?\`) prefixes, and validates both the lexical path and
    /// canonicalized parent path.
    pub fn check_path(path: &Path) -> Result<(), SafetyError> {
        let raw_str = path.to_string_lossy();
        if raw_str.trim().is_empty() {
            return Err(SafetyError::ProtectedPath(path.display().to_string()));
        }

        let norm = normalize_and_strip_verbatim(&raw_str);
        // Block any relative parent traversal (`..`) regardless of platform slash style
        if path.components().any(|c| matches!(c, Component::ParentDir))
            || norm.split('/').any(|seg| seg == "..")
        {
            return Err(SafetyError::ProtectedPath(path.display().to_string()));
        }

        let homes = resolve_candidate_homes();
        Self::check_lexical_norm(&norm, path, &homes)?;
        Self::check_ancestors_and_canonical(path, &homes)?;
        Ok(())
    }

    fn check_lexical_norm(norm: &str, original: &Path, homes: &[String]) -> Result<(), SafetyError> {
        let trimmed = if norm.len() > 1 {
            norm.trim_end_matches('/')
        } else {
            norm
        };
        let lower = trimmed.to_ascii_lowercase();

        // 1. Never touch credentials, VCS metadata, keychains, or ClearLens internal state at any depth.
        for seg in lower.split('/').filter(|s| !s.is_empty()) {
            if matches!(
                seg,
                ".ssh"
                    | ".gnupg"
                    | ".aws"
                    | ".kube"
                    | ".azure"
                    | ".git"
                    | ".hg"
                    | ".svn"
                    | ".password-store"
                    | "keychains"
                    | ".clearlens"
            ) {
                return Err(SafetyError::ProtectedPath(original.display().to_string()));
            }
        }

        // 1b. Never allow deleting raw hypervisor / WSL2 / Docker / OrbStack / Lima virtual disks.
        if is_protected_virtual_disk_path(&lower) {
            return Err(SafetyError::ProtectedPath(original.display().to_string()));
        }

        // 1c. Never touch browser credentials, cookies, bookmarks, history, or local storage databases.
        if is_protected_browser_secret_path(&lower) {
            return Err(SafetyError::ProtectedPath(original.display().to_string()));
        }

        // 2. Protect OS roots and critical system directories on macOS, Linux, and Windows.
        if matches!(
            lower.as_str(),
            "/" | "/etc" | "/var" | "/private" | "/applications" | "/users" | "/home"
        ) {
            return Err(SafetyError::ProtectedPath(original.display().to_string()));
        }

        for sys_prefix in [
            "/system",
            "/usr",
            "/bin",
            "/sbin",
            "/etc",
            "/private/etc",
            "/var/db",
            "/private/var/db",
            "/var/root",
            "/library/extensions",
        ] {
            if lower == sys_prefix || lower.starts_with(&format!("{sys_prefix}/")) {
                return Err(SafetyError::ProtectedPath(original.display().to_string()));
            }
        }

        // Drive-letter agnostic Windows protections (C:, D:, E:, etc., including unprefixed \\?\ paths)
        if is_windows_drive_path(&lower) {
            if lower.len() == 2 {
                return Err(SafetyError::ProtectedPath(original.display().to_string()));
            }
            let after_drive = &lower[2..];
            if matches!(
                after_drive,
                "/windows" | "/program files" | "/program files (x86)" | "/programdata" | "/users"
            ) || after_drive.starts_with("/programdata/")
                || after_drive == "/windows/system32"
                || after_drive.starts_with("/windows/system32/")
                || after_drive == "/windows/winsxs"
                || after_drive.starts_with("/windows/winsxs/")
            {
                return Err(SafetyError::ProtectedPath(original.display().to_string()));
            }
            if after_drive.starts_with("/windows/") && !is_allowed_windows_cache_rel(after_drive) {
                return Err(SafetyError::ProtectedPath(original.display().to_string()));
            }
            if (after_drive.starts_with("/program files/")
                || after_drive.starts_with("/program files (x86)/"))
                && !is_allowed_steam_cache(&lower)
            {
                return Err(SafetyError::ProtectedPath(original.display().to_string()));
            }
        }

        // 3. Protect user personal folders relative to HOME / USERPROFILE (and canonical HOME).
        for home_trimmed in homes {
            if lower == *home_trimmed {
                return Err(SafetyError::ProtectedPath(original.display().to_string()));
            }
            if let Some(rel) = lower.strip_prefix(&format!("{home_trimmed}/")) {
                Self::check_home_relative_subpath(rel, original)?;
            }
        }

        Ok(())
    }

    fn check_ancestors_and_canonical(path: &Path, homes: &[String]) -> Result<(), SafetyError> {
        let Some(parent) = path.parent() else {
            return Ok(());
        };
        if parent.as_os_str().is_empty() {
            return Ok(());
        }

        // Collect ancestor chain from root down to `parent`
        let mut chain: Vec<&Path> = parent.ancestors().collect();
        chain.reverse();

        let mut deepest_existing: Option<&Path> = None;
        for anc in chain {
            if anc.as_os_str().is_empty() {
                continue;
            }
            let Ok(meta) = fs::symlink_metadata(anc) else {
                break;
            };
            deepest_existing = Some(anc);
            if is_metadata_reparse_or_symlink(&meta) && !is_os_root_compat_symlink(anc) {
                return Err(SafetyError::SymlinkBlocked(path.display().to_string()));
            }
        }

        if let Some(existing_anc) = deepest_existing {
            if let Ok(canon_anc) = fs::canonicalize(existing_anc) {
                let mut resolved: PathBuf = canon_anc;
                if let Ok(tail) = path.strip_prefix(existing_anc) {
                    resolved.push(tail);
                }
                let resolved_norm = normalize_and_strip_verbatim(&resolved.to_string_lossy());
                Self::check_lexical_norm(&resolved_norm, path, homes)?;
            }
        }

        Ok(())
    }

    fn check_home_relative_subpath(rel_lower: &str, original: &Path) -> Result<(), SafetyError> {
        let parts: Vec<&str> = rel_lower.split('/').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            return Err(SafetyError::ProtectedPath(original.display().to_string()));
        }

        // Block sensitive user dotfiles / CLI auth tokens under $HOME
        if matches!(
            parts[0],
            ".npmrc" | ".pypirc" | ".netrc" | ".gitconfig" | ".git-credentials"
        ) {
            return Err(SafetyError::ProtectedPath(original.display().to_string()));
        }
        if parts.len() >= 2 && parts[0] == ".docker" && parts[1] == "config.json" {
            return Err(SafetyError::ProtectedPath(original.display().to_string()));
        }
        if parts.len() >= 2 && parts[0] == ".config" && matches!(parts[1], "gcloud" | "gh") {
            return Err(SafetyError::ProtectedPath(original.display().to_string()));
        }

        match parts[0] {
            "desktop" | "pictures" | "music" => {
                Err(SafetyError::ProtectedPath(original.display().to_string()))
            }
            "documents" => {
                // Only deep, explicitly scoped IM cache subdirectories inside Documents are permitted.
                if is_allowed_documents_im_cache(rel_lower) {
                    Ok(())
                } else {
                    Err(SafetyError::ProtectedPath(original.display().to_string()))
                }
            }
            "movies" | "videos" => {
                if is_allowed_media_cache(rel_lower) {
                    Ok(())
                } else {
                    Err(SafetyError::ProtectedPath(original.display().to_string()))
                }
            }
            _ => Ok(()),
        }
    }
}

/// Checks metadata directly for symlinks and Windows NTFS reparse points (junctions, volume mount points).
pub fn is_metadata_reparse_or_symlink(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as WinMetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return true;
        }
    }
    false
}

fn is_protected_virtual_disk_path(lower: &str) -> bool {
    if lower.ends_with(".vhdx") {
        return true;
    }
    if lower.ends_with("/docker.raw") && lower.contains("com.docker.docker") {
        return true;
    }
    if lower.ends_with("/data.img") && lower.contains(".dev.orbstack") {
        return true;
    }
    if lower.ends_with("/diffdisk")
        && (lower.contains("/.lima/") || lower.contains("/.colima/_lima/"))
    {
        return true;
    }
    false
}

fn is_protected_browser_secret_path(lower: &str) -> bool {
    const BROWSER_MARKERS: &[&str] = &[
        "google/chrome",
        "microsoft/edge",
        "microsoft edge",
        "bravesoftware",
        "thebrowsercompany.arc",
        "arc/user data",
        "mozilla/firefox",
        "com.apple.safari",
    ];
    let Some(pos) = BROWSER_MARKERS.iter().filter_map(|m| lower.find(m)).min() else {
        return false;
    };
    let tail = &lower[pos..];
    for seg in tail.split('/').filter(|s| !s.is_empty()) {
        if matches!(
            seg,
            "cookies"
                | "cookies-journal"
                | "login data"
                | "login data-journal"
                | "login data for account"
                | "web data"
                | "web data-journal"
                | "bookmarks"
                | "bookmarks.bak"
                | "history"
                | "history-journal"
                | "favicons"
                | "places.sqlite"
                | "key4.db"
                | "logins.json"
                | "cert9.db"
                | "local storage"
                | "session storage"
                | "indexeddb"
                | "extension state"
                | "sync data"
        ) {
            return true;
        }
    }
    false
}

fn resolve_candidate_homes() -> Vec<String> {
    let mut raw_homes = Vec::new();
    if let Some(h) = resolve_home_dir() {
        raw_homes.push(h);
    }
    if let Some(up) = std::env::var_os("USERPROFILE").filter(|v| !v.is_empty()) {
        raw_homes.push(PathBuf::from(up));
    }
    if let Some(dh) = dirs::home_dir() {
        raw_homes.push(dh);
    }

    let mut out = Vec::new();
    for home in raw_homes {
        let norm = normalize_and_strip_verbatim(&home.to_string_lossy())
            .trim_end_matches('/')
            .to_ascii_lowercase();
        if !norm.is_empty() && !out.contains(&norm) {
            out.push(norm);
        }
        if let Ok(canon) = fs::canonicalize(&home) {
            let cnorm = normalize_and_strip_verbatim(&canon.to_string_lossy())
                .trim_end_matches('/')
                .to_ascii_lowercase();
            if !cnorm.is_empty() && !out.contains(&cnorm) {
                out.push(cnorm);
            }
        }
    }
    out
}

fn is_windows_drive_path(lower: &str) -> bool {
    let b = lower.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

fn normalize_and_strip_verbatim(raw: &str) -> String {
    let slashes = normalize_slashes(raw);
    let lower = slashes.to_ascii_lowercase();
    let unprefixed = if lower.starts_with("//?/unc/") {
        format!("/{}", &slashes["//?/unc/".len()..])
    } else if lower.starts_with("//?/") || lower.starts_with("//./") {
        slashes[4..].to_string()
    } else {
        slashes
    };
    let collapsed = collapse_slashes(&unprefixed);
    let clower = collapsed.to_ascii_lowercase();
    for prefix in ["/?/", "/./"] {
        if let Some(after) = clower.strip_prefix(prefix) {
            if is_windows_drive_path(after) {
                return collapsed[prefix.len()..].to_string();
            }
        }
    }
    collapsed
}

fn is_os_root_compat_symlink(anc: &Path) -> bool {
    let norm = collapse_slashes(&normalize_slashes(&anc.to_string_lossy()));
    matches!(norm.as_str(), "/var" | "/tmp" | "/etc" | "/home")
}

fn collapse_slashes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_slash = false;
    for ch in s.chars() {
        if ch == '/' {
            if !prev_slash {
                out.push('/');
            }
            prev_slash = true;
        } else {
            prev_slash = false;
            out.push(ch);
        }
    }
    out
}

fn is_allowed_windows_cache_rel(after_drive: &str) -> bool {
    after_drive == "/windows/softwaredistribution/download"
        || after_drive.starts_with("/windows/softwaredistribution/download/")
        || after_drive == "/windows/temp"
        || after_drive.starts_with("/windows/temp/")
}

fn is_allowed_steam_cache(lower: &str) -> bool {
    lower.contains("/steam/appcache/httpcache")
        || lower.contains("/steam/steamapps/shadercache")
        || lower.contains("/steam/dumps")
}

fn is_allowed_documents_im_cache(rel_lower: &str) -> bool {
    if rel_lower.contains("/filestorage/file")
        || rel_lower.contains("/filestorage/msgattach")
        || rel_lower.contains("/filerecv")
        || rel_lower.ends_with(".db")
        || rel_lower.ends_with(".sqlite")
    {
        return false;
    }
    let has_app_root = rel_lower.starts_with("documents/wechat files/")
        || rel_lower.starts_with("documents/wxwork/")
        || rel_lower.starts_with("documents/tencent files/");
    let has_cache_leaf = rel_lower.contains("/filestorage/cache")
        || rel_lower.contains("/filestorage/video")
        || rel_lower.contains("/cache/")
        || rel_lower.ends_with("/cache")
        || rel_lower.contains("/image/c2c");
    has_app_root && has_cache_leaf
}

fn is_allowed_media_cache(rel_lower: &str) -> bool {
    rel_lower.contains("/user data/cache")
        || rel_lower.contains("/render files")
        || rel_lower.contains("/cacheclip")
}

/// Validates a glob pattern inside a TOML rule file to block overly broad or dangerous targets.
pub fn validate_rule_pattern(pattern: &str) -> Result<(), SafetyError> {
    let norm = normalize_and_strip_verbatim(pattern).to_ascii_lowercase();
    let trimmed_raw = norm.trim();
    let trimmed = if trimmed_raw.len() > 1 {
        trimmed_raw.trim_end_matches('/')
    } else {
        trimmed_raw
    };
    if trimmed.is_empty() || trimmed == "/" || trimmed == "*" || trimmed == "**" {
        return Err(SafetyError::UnsafeRulePattern(pattern.to_string()));
    }

    // Block traversal segments (`..`), credentials/VCS folders, ClearLens state, and virtual disk images
    for seg in trimmed.split('/').filter(|s| !s.is_empty()) {
        if seg == ".."
            || matches!(
                seg,
                ".ssh"
                    | ".gnupg"
                    | ".aws"
                    | ".kube"
                    | ".azure"
                    | "keychains"
                    | ".git"
                    | ".hg"
                    | ".svn"
                    | ".password-store"
                    | ".clearlens"
            )
        {
            return Err(SafetyError::UnsafeRulePattern(pattern.to_string()));
        }
    }
    if trimmed.ends_with(".vhdx") || trimmed.ends_with("/docker.raw") {
        return Err(SafetyError::UnsafeRulePattern(pattern.to_string()));
    }

    // Block shallow `/users*` and `/home*` prefixes
    if matches!(
        trimmed,
        "/users" | "/users/*" | "/users/**" | "/home" | "/home/*" | "/home/**"
    ) {
        return Err(SafetyError::UnsafeRulePattern(pattern.to_string()));
    }

    // Block broad `%appdata%/*`, `%appdata%/**`, `%localappdata%/*`, `%localappdata%/**`
    if matches!(
        trimmed,
        "%appdata%"
            | "%appdata%/*"
            | "%appdata%/**"
            | "%localappdata%"
            | "%localappdata%/*"
            | "%localappdata%/**"
    ) {
        return Err(SafetyError::UnsafeRulePattern(pattern.to_string()));
    }

    // Block Unix critical system prefixes
    for sys_prefix in [
        "/system",
        "/usr",
        "/bin",
        "/sbin",
        "/etc",
        "/private/etc",
        "/var/db",
        "/private/var/db",
        "/var/root",
        "/applications",
    ] {
        if trimmed == sys_prefix || trimmed.starts_with(&format!("{sys_prefix}/")) {
            return Err(SafetyError::UnsafeRulePattern(pattern.to_string()));
        }
    }

    // Block `%windir%` outside scoped cache paths
    if trimmed == "%windir%" || trimmed.starts_with("%windir%/") {
        let allowed = trimmed == "%windir%/softwaredistribution/download"
            || trimmed.starts_with("%windir%/softwaredistribution/download/")
            || trimmed == "%windir%/temp"
            || trimmed.starts_with("%windir%/temp/");
        if !allowed {
            return Err(SafetyError::UnsafeRulePattern(pattern.to_string()));
        }
    }

    // Block `%programfiles%` and `%programfiles(x86)%` outside Steam caches
    if (trimmed == "%programfiles%"
        || trimmed == "%programfiles(x86)%"
        || trimmed.starts_with("%programfiles%/")
        || trimmed.starts_with("%programfiles(x86)%/"))
        && !is_allowed_steam_cache(trimmed)
    {
        return Err(SafetyError::UnsafeRulePattern(pattern.to_string()));
    }

    // Block `<drive>:`, `<drive>:/**`, `<drive>:/windows`, `<drive>:/program files*`, `<drive>:/programdata`, `<drive>:/users*`
    let mut win_user_rel: Option<&str> = None;
    if is_windows_drive_path(trimmed) {
        let after_drive = &trimmed[2..];
        if matches!(
            after_drive,
            "" | "/*" | "/**" | "/users" | "/users/*" | "/users/**"
        ) {
            return Err(SafetyError::UnsafeRulePattern(pattern.to_string()));
        }
        if after_drive == "/programdata" || after_drive.starts_with("/programdata/") {
            return Err(SafetyError::UnsafeRulePattern(pattern.to_string()));
        }
        if (after_drive == "/windows" || after_drive.starts_with("/windows/"))
            && !is_allowed_windows_cache_rel(after_drive)
        {
            return Err(SafetyError::UnsafeRulePattern(pattern.to_string()));
        }
        if (after_drive == "/program files"
            || after_drive == "/program files (x86)"
            || after_drive.starts_with("/program files/")
            || after_drive.starts_with("/program files (x86)/"))
            && !is_allowed_steam_cache(trimmed)
        {
            return Err(SafetyError::UnsafeRulePattern(pattern.to_string()));
        }
        if let Some(after_users) = after_drive.strip_prefix("/users/") {
            let Some((_, tail)) = after_users.split_once('/') else {
                return Err(SafetyError::UnsafeRulePattern(pattern.to_string()));
            };
            win_user_rel = Some(tail);
        }
    }

    // Reject shallow home-level wildcards such as "~/*", "~/**", "%USERPROFILE%/*", "$HOME/**"
    let stripped = if let Some(rel) = win_user_rel {
        rel
    } else if let Some(after_users) = trimmed
        .strip_prefix("/users/")
        .or_else(|| trimmed.strip_prefix("/home/"))
    {
        let Some((_, tail)) = after_users.split_once('/') else {
            return Err(SafetyError::UnsafeRulePattern(pattern.to_string()));
        };
        tail
    } else {
        trimmed
            .strip_prefix("~/")
            .or_else(|| trimmed.strip_prefix("$home/"))
            .or_else(|| trimmed.strip_prefix("%userprofile%/"))
            .unwrap_or(trimmed)
    };

    let segs: Vec<&str> = stripped.split('/').filter(|s| !s.is_empty()).collect();
    if segs.is_empty() || segs[0] == "*" || segs[0] == "**" {
        return Err(SafetyError::UnsafeRulePattern(pattern.to_string()));
    }

    if matches!(
        segs[0],
        ".npmrc" | ".pypirc" | ".netrc" | ".gitconfig" | ".git-credentials"
    ) {
        return Err(SafetyError::UnsafeRulePattern(pattern.to_string()));
    }
    if segs.len() >= 2 && segs[0] == ".config" && matches!(segs[1], "gcloud" | "gh") {
        return Err(SafetyError::UnsafeRulePattern(pattern.to_string()));
    }

    // Reject overly broad app-data container wipe globs
    if segs[0] == "library"
        && (segs.len() == 1
            || (segs.len() == 2 && matches!(segs[1], "*" | "**" | "application support" | "containers"))
            || (segs.len() == 3
                && matches!(segs[1], "application support" | "containers")
                && matches!(segs[2], "*" | "**")))
    {
        return Err(SafetyError::UnsafeRulePattern(pattern.to_string()));
    }
    if segs.len() >= 2
        && segs[0] == "appdata"
        && matches!(segs[1], "local" | "roaming")
        && (segs.len() == 2 || (segs.len() == 3 && matches!(segs[2], "*" | "**")))
    {
        return Err(SafetyError::UnsafeRulePattern(pattern.to_string()));
    }

    if matches!(segs[0], "desktop" | "pictures" | "music") {
        return Err(SafetyError::UnsafeRulePattern(pattern.to_string()));
    }
    if segs[0] == "documents" && !is_allowed_documents_im_cache(&segs.join("/")) {
        return Err(SafetyError::UnsafeRulePattern(pattern.to_string()));
    }
    if matches!(segs[0], "movies" | "videos") && !is_allowed_media_cache(&segs.join("/")) {
        return Err(SafetyError::UnsafeRulePattern(pattern.to_string()));
    }

    Ok(())
}

pub fn validate_rule_file_patterns(rule_file: &RuleFile) -> Result<(), SafetyError> {
    for rule in &rule_file.rules {
        for pat in rule
            .paths
            .macos
            .iter()
            .chain(rule.paths.windows.iter())
            .chain(rule.paths.linux.iter())
        {
            validate_rule_pattern(pat)?;
        }
    }
    Ok(())
}

pub fn normalize_slashes(s: &str) -> String {
    s.replace('\\', "/")
}

/// Checks if a path is a symlink or reparse point (never follow).
pub fn is_symlink_or_reparse(path: &Path) -> bool {
    inspect_path_meta(path)
        .map(|m| m.is_symlink_or_reparse)
        .unwrap_or(false)
}

/// 32-shard hardlink deduplicator keyed by (dev, ino).
pub struct HardlinkDeduplicator {
    shards: [Mutex<FxHashSet<(u64, u64)>>; 32],
}

impl Default for HardlinkDeduplicator {
    fn default() -> Self {
        Self {
            shards: std::array::from_fn(|_| Mutex::new(FxHashSet::default())),
        }
    }
}

impl HardlinkDeduplicator {
    /// Returns true if this file should be counted (first time seeing this (dev, ino) or nlink <= 1).
    pub fn should_count(&self, dev: u64, ino: u64, nlink: u64) -> bool {
        if nlink <= 1 || (dev == 0 && ino == 0) {
            return true;
        }
        let idx = ((dev ^ ino) as usize) & 31;
        let mut guard = self.shards[idx].lock().expect("hardlink shard mutex poisoned");
        guard.insert((dev, ino))
    }
}

/// Captures a snapshot of running process names (lowercased) for lock detection.
pub struct ProcessMonitor {
    running_names: FxHashSet<String>,
}

impl ProcessMonitor {
    pub fn snapshot() -> Self {
        let Ok(mut sys) = System::new_with_specifics(
            RefreshKind::nothing().with_processes(ProcessRefreshKind::nothing()),
        ) else {
            return Self {
                running_names: FxHashSet::default(),
            };
        };
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        let running_names = sys
            .processes()
            .values()
            .map(|p| p.name().to_string_lossy().to_ascii_lowercase())
            .collect();
        Self { running_names }
    }

    pub fn find_running(&self, candidates: &[String]) -> Option<String> {
        for cand in candidates {
            let lower = cand.trim().to_ascii_lowercase();
            if lower.is_empty() {
                continue;
            }
            let stem = lower.strip_suffix(".exe").unwrap_or(&lower);
            if self.running_names.iter().any(|r| {
                let r_stem = r.strip_suffix(".exe").unwrap_or(r.as_str());
                r == &lower || r == stem || r_stem == stem
            }) {
                return Some(cand.clone());
            }
        }
        None
    }
}
