export type TargetPlatform = "macos" | "windows" | "linux";
export type RiskLevel = "safe" | "recreatable" | "review_required";
export type DeleteMode = "permanent" | "trash" | "native_command";

export interface ScanHit {
  id: string;
  rule_id: string;
  category: string;
  app_name: string;
  app_name_zh: string;
  title: string;
  title_zh: string;
  risk: RiskLevel;
  default_checked: boolean;
  delete_mode: DeleteMode;
  requires_elevation: boolean;
  path: string;
  allocated_bytes: number;
  file_count: number;
  last_modified_ts: number;
  impact_note: string;
  impact_note_zh: string;
  locked_by_process: string | null;
  native_command: string | null;
}

export interface CategorySummary {
  category: string;
  total_bytes: number;
  file_count: number;
  hit_count: number;
}

export interface RiskSummary {
  safe_bytes: number;
  recreatable_bytes: number;
  review_required_bytes: number;
}

export interface ScanReport {
  platform: TargetPlatform;
  duration_ms: number;
  total_reclaimable_bytes: number;
  total_files: number;
  skipped_warnings: number;
  risk_summary: RiskSummary;
  categories: CategorySummary[];
  hits: ScanHit[];
}

export type ScanProgressEvent =
  | { event: "RuleMatched"; data: { rule_id: string; added_bytes: number; added_files: number } }
  | { event: "DirectoryStatUpdated"; data: { current_path: string; scanned_files: number; scanned_bytes: number } }
  | { event: "WarningSkipped"; data: { path: string; reason: string } }
  | { event: "Completed"; data: { duration_ms: number; total_reclaimable_bytes: number; hit_count: number } };

export interface VolumeInfo {
  mount_point: string;
  label: string;
  total_bytes: number;
  available_bytes: number;
  used_bytes: number;
  purgeable_bytes: number;
  is_system: boolean;
}

export interface DiskOverview {
  platform: TargetPlatform;
  mount_point: string;
  total_bytes: number;
  available_bytes: number;
  used_bytes: number;
  purgeable_bytes: number;
  important_available_bytes: number;
  fda_granted: boolean;
  local_snapshots_count: number;
  rule_count: number;
  volumes?: VolumeInfo[];
}

export interface SpaceNode {
  name: string;
  path: string;
  allocated_bytes: number;
  file_count: number;
  is_dir: boolean;
  is_synthetic_other: boolean;
  has_more_children?: boolean;
  children: SpaceNode[];
}

export interface ColdFileEntry {
  path: string;
  name: string;
  allocated_bytes: number;
  last_modified_ts: number;
  inactive_days: number;
}

export interface SpaceLensReport {
  root: SpaceNode;
  cold_files: ColdFileEntry[];
  duration_ms: number;
  skipped_cloud_placeholders: number;
  skipped_symlinks: number;
  skipped_permission_errors: number;
}

export interface CleanItemRequest {
  rule_id: string;
  path: string;
  risk: RiskLevel;
  delete_mode: DeleteMode;
  native_command: string | null;
}

export interface CleanReport {
  dry_run: boolean;
  duration_ms: number;
  total_freed_bytes: number;
  succeeded_count: number;
  failed_count: number;
  outcomes: {
    rule_id: string;
    path: string;
    actual_mode: DeleteMode;
    freed_bytes: number;
    success: boolean;
    error: string | null;
  }[];
}

export interface RuleFile {
  schema_version: number;
  category: string;
  app_name: string;
  app_name_zh: string;
  rules: {
    id: string;
    title: string;
    title_zh: string;
    kind: string;
    risk: RiskLevel;
    default_checked: boolean;
    delete_mode: DeleteMode;
    impact_note: string;
    impact_note_zh: string;
  }[];
}

export interface AuditRecord {
  timestamp: string;
  rule_id: string;
  path: string;
  bytes_freed: number;
  method: string;
  success: boolean;
  note: string | null;
}

export interface AppConfig {
  ignore_paths: string[];
  workspace_roots: string[];
  default_stale_days: number;
}

export interface DuplicateFileEntry {
  path: string;
  name: string;
  allocated_bytes: number;
  logical_bytes: number;
  mtime_secs: number;
  recommended_keep: boolean;
}

export interface DuplicateGroup {
  blake3_hash: string;
  file_size: number;
  wasted_bytes: number;
  entries: DuplicateFileEntry[];
}

export interface DuplicateReport {
  duration_ms: number;
  scanned_files: number;
  candidate_files: number;
  total_wasted_bytes: number;
  skipped_hardlinks: number;
  skipped_cloud_placeholders: number;
  groups: DuplicateGroup[];
}

export interface DuplicateCleanGroup {
  blake3_hash: string;
  all_paths: string[];
  delete_paths: string[];
}

export interface AppResidueItem {
  path: string;
  kind: string;
  allocated_bytes: number;
  file_count: number;
}

export interface InstalledAppEntry {
  name: string;
  bundle_id: string | null;
  install_path: string;
  app_bytes: number;
  residue_bytes: number;
  residues: AppResidueItem[];
}

export interface OrphanResidue {
  name: string;
  path: string;
  location_kind: string;
  allocated_bytes: number;
  file_count: number;
  last_modified_ts: number;
  inactive_days: number;
}

export interface UninstallerReport {
  platform: TargetPlatform;
  duration_ms: number;
  apps: InstalledAppEntry[];
  orphans: OrphanResidue[];
  total_orphan_bytes: number;
}

export interface VirtualDiskEntry {
  id: string;
  kind: string;
  name: string;
  path: string;
  allocated_bytes: number;
  logical_bytes: number;
  sparse_savings_bytes: number;
  is_in_use: boolean;
  requires_elevation: boolean;
  compact_command: string;
  compact_script: string;
  safety_note: string;
  safety_note_zh: string;
}

export interface VirtualDiskReport {
  platform: TargetPlatform;
  duration_ms: number;
  total_allocated_bytes: number;
  total_logical_bytes: number;
  disks: VirtualDiskEntry[];
}
