use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetPlatform {
    MacOs,
    Windows,
    Linux,
}

impl TargetPlatform {
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::MacOs
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else {
            Self::Linux
        }
    }

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "mac" | "macos" | "darwin" => Some(Self::MacOs),
            "win" | "windows" => Some(Self::Windows),
            "linux" => Some(Self::Linux),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Safe,
    Recreatable,
    ReviewRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeleteMode {
    Permanent,
    Trash,
    NativeCommand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    Glob,
    SmartScanner,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlatformPaths {
    #[serde(default)]
    pub macos: Vec<String>,
    #[serde(default)]
    pub windows: Vec<String>,
    #[serde(default)]
    pub linux: Vec<String>,
}

impl PlatformPaths {
    pub fn for_platform(&self, platform: TargetPlatform) -> &[String] {
        match platform {
            TargetPlatform::MacOs => &self.macos,
            TargetPlatform::Windows => &self.windows,
            TargetPlatform::Linux => &self.linux,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleExclude {
    #[serde(default)]
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDef {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub title_zh: String,
    pub kind: RuleKind,
    #[serde(default)]
    pub scanner: Option<String>,
    pub risk: RiskLevel,
    #[serde(default)]
    pub default_checked: bool,
    pub delete_mode: DeleteMode,
    #[serde(default)]
    pub requires_elevation: bool,
    #[serde(default)]
    pub min_age_days: u32,
    #[serde(default)]
    pub impact_note: String,
    #[serde(default)]
    pub impact_note_zh: String,
    #[serde(default)]
    pub paths: PlatformPaths,
    #[serde(default)]
    pub exclude: RuleExclude,
    #[serde(default)]
    pub params: HashMap<String, toml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleFile {
    pub schema_version: u32,
    pub category: String,
    pub app_name: String,
    #[serde(default)]
    pub app_name_zh: String,
    #[serde(default)]
    pub process_names_win: Vec<String>,
    #[serde(default)]
    pub process_names_mac: Vec<String>,
    pub rules: Vec<RuleDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanHit {
    pub id: String,
    pub rule_id: String,
    pub category: String,
    pub app_name: String,
    pub app_name_zh: String,
    pub title: String,
    pub title_zh: String,
    pub risk: RiskLevel,
    pub default_checked: bool,
    pub delete_mode: DeleteMode,
    pub requires_elevation: bool,
    pub path: PathBuf,
    pub allocated_bytes: u64,
    pub file_count: u64,
    pub last_modified_ts: i64,
    pub impact_note: String,
    pub impact_note_zh: String,
    pub locked_by_process: Option<String>,
    pub native_command: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorySummary {
    pub category: String,
    pub total_bytes: u64,
    pub file_count: u64,
    pub hit_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskSummary {
    pub safe_bytes: u64,
    pub recreatable_bytes: u64,
    pub review_required_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub platform: TargetPlatform,
    pub duration_ms: u64,
    pub total_reclaimable_bytes: u64,
    pub total_files: u64,
    pub skipped_warnings: usize,
    pub risk_summary: RiskSummary,
    pub categories: Vec<CategorySummary>,
    pub hits: Vec<ScanHit>,
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub platform: TargetPlatform,
    pub categories: Option<Vec<String>>,
    pub stale_days: u32,
    pub workspace_roots: Vec<PathBuf>,
    pub ignore_paths: Vec<PathBuf>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            platform: TargetPlatform::current(),
            categories: None,
            stale_days: 30,
            workspace_roots: Vec::new(),
            ignore_paths: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", content = "data")]
pub enum ScanProgressEvent {
    RuleMatched {
        rule_id: String,
        added_bytes: u64,
        added_files: u64,
    },
    DirectoryStatUpdated {
        current_path: String,
        scanned_files: u64,
        scanned_bytes: u64,
    },
    WarningSkipped {
        path: String,
        reason: String,
    },
    Completed {
        duration_ms: u64,
        total_reclaimable_bytes: u64,
        hit_count: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeInfo {
    pub mount_point: String,
    pub label: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,
    pub purgeable_bytes: u64,
    pub is_system: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskOverview {
    pub platform: TargetPlatform,
    pub mount_point: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,
    pub purgeable_bytes: u64,
    pub important_available_bytes: u64,
    pub fda_granted: bool,
    pub local_snapshots_count: usize,
    pub rule_count: usize,
    #[serde(default)]
    pub volumes: Vec<VolumeInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaceNode {
    pub name: String,
    pub path: PathBuf,
    pub allocated_bytes: u64,
    pub file_count: u64,
    pub is_dir: bool,
    pub is_synthetic_other: bool,
    #[serde(default)]
    pub has_more_children: bool,
    pub children: Vec<SpaceNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColdFileEntry {
    pub path: PathBuf,
    pub name: String,
    pub allocated_bytes: u64,
    pub last_modified_ts: i64,
    pub inactive_days: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaceLensReport {
    pub root: SpaceNode,
    pub cold_files: Vec<ColdFileEntry>,
    pub duration_ms: u64,
    pub skipped_cloud_placeholders: u64,
    pub skipped_symlinks: u64,
    pub skipped_permission_errors: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanItemRequest {
    pub rule_id: String,
    pub path: PathBuf,
    pub risk: RiskLevel,
    pub delete_mode: DeleteMode,
    pub native_command: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanItemOutcome {
    pub rule_id: String,
    pub path: PathBuf,
    pub requested_mode: DeleteMode,
    pub actual_mode: DeleteMode,
    pub freed_bytes: u64,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanReport {
    pub dry_run: bool,
    pub duration_ms: u64,
    pub total_freed_bytes: u64,
    pub succeeded_count: usize,
    pub failed_count: usize,
    pub outcomes: Vec<CleanItemOutcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub timestamp: String,
    pub rule_id: String,
    pub path: PathBuf,
    pub bytes_freed: u64,
    pub method: String,
    pub success: bool,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub ignore_paths: Vec<PathBuf>,
    #[serde(default)]
    pub workspace_roots: Vec<PathBuf>,
    #[serde(default = "default_stale_days")]
    pub default_stale_days: u32,
}

fn default_stale_days() -> u32 {
    30
}

// ============================================================================
// P0 On-Demand Elevation Worker Protocol
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", content = "payload", rename_all = "snake_case")]
pub enum ElevationAction {
    CleanElevatedPaths {
        items: Vec<CleanItemRequest>,
        dry_run: bool,
    },
    MacOsThinSnapshots {
        bytes_to_free: u64,
        dry_run: bool,
    },
    WindowsDismCleanup {
        dry_run: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElevationRequest {
    pub request_id: String,
    pub action: ElevationAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElevationResult {
    pub request_id: String,
    pub success: bool,
    pub message: String,
    pub clean_report: Option<CleanReport>,
}

// ============================================================================
// P1 BLAKE3 Duplicate File Finder Models
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateFileEntry {
    pub path: PathBuf,
    pub name: String,
    pub allocated_bytes: u64,
    pub logical_bytes: u64,
    pub mtime_secs: i64,
    pub recommended_keep: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateGroup {
    pub blake3_hash: String,
    pub file_size: u64,
    pub wasted_bytes: u64,
    pub entries: Vec<DuplicateFileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateReport {
    pub duration_ms: u64,
    pub scanned_files: u64,
    pub candidate_files: u64,
    pub total_wasted_bytes: u64,
    pub skipped_hardlinks: u64,
    pub skipped_cloud_placeholders: u64,
    pub groups: Vec<DuplicateGroup>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateCleanGroup {
    pub blake3_hash: String,
    pub all_paths: Vec<PathBuf>,
    pub delete_paths: Vec<PathBuf>,
}

// ============================================================================
// P1 App Uninstaller & Orphan Residue Hunter Models
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppResidueItem {
    pub path: PathBuf,
    pub kind: String,
    pub allocated_bytes: u64,
    pub file_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledAppEntry {
    pub name: String,
    pub bundle_id: Option<String>,
    pub install_path: PathBuf,
    pub app_bytes: u64,
    pub residue_bytes: u64,
    pub residues: Vec<AppResidueItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrphanResidue {
    pub name: String,
    pub path: PathBuf,
    pub location_kind: String,
    pub allocated_bytes: u64,
    pub file_count: u64,
    pub last_modified_ts: i64,
    pub inactive_days: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UninstallerReport {
    pub platform: TargetPlatform,
    pub duration_ms: u64,
    pub apps: Vec<InstalledAppEntry>,
    pub orphans: Vec<OrphanResidue>,
    pub total_orphan_bytes: u64,
}

// ============================================================================
// Virtual Disk (WSL2 / Docker / OrbStack / Lima) Compaction Inspector Models
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VirtualDiskKind {
    Wsl2Vhdx,
    DockerDesktopVhdx,
    DockerDesktopRawMac,
    OrbStackImage,
    LimaColimaDisk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualDiskEntry {
    pub id: String,
    pub kind: VirtualDiskKind,
    pub name: String,
    pub path: PathBuf,
    pub allocated_bytes: u64,
    pub logical_bytes: u64,
    pub sparse_savings_bytes: u64,
    pub is_in_use: bool,
    pub requires_elevation: bool,
    pub compact_command: String,
    pub compact_script: String,
    pub safety_note: String,
    pub safety_note_zh: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualDiskReport {
    pub platform: TargetPlatform,
    pub duration_ms: u64,
    pub total_allocated_bytes: u64,
    pub total_logical_bytes: u64,
    pub disks: Vec<VirtualDiskEntry>,
}
