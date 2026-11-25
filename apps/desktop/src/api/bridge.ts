import { Channel, invoke } from "@tauri-apps/api/core";
import type {
  AppConfig,
  AuditRecord,
  CleanItemRequest,
  CleanReport,
  DiskOverview,
  DuplicateCleanGroup,
  DuplicateReport,
  RuleFile,
  ScanHit,
  ScanProgressEvent,
  ScanReport,
  SpaceLensReport,
  SpaceNode,
  UninstallerReport,
  VirtualDiskReport,
} from "../types";

export function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export const DEMO_OVERVIEW: DiskOverview = {
  platform: "macos",
  mount_point: "/",
  total_bytes: 1_000_000_000_000,
  available_bytes: 214_600_000_000,
  used_bytes: 785_400_000_000,
  purgeable_bytes: 42_800_000_000,
  important_available_bytes: 257_400_000_000,
  fda_granted: true,
  local_snapshots_count: 2,
  rule_count: 39,
  volumes: [
    {
      mount_point: "/",
      label: "Macintosh HD",
      total_bytes: 1_000_000_000_000,
      available_bytes: 214_600_000_000,
      used_bytes: 785_400_000_000,
      purgeable_bytes: 42_800_000_000,
      is_system: true,
    },
    {
      mount_point: "/Volumes/WorkSSD",
      label: "WorkSSD",
      total_bytes: 2_000_000_000_000,
      available_bytes: 890_000_000_000,
      used_bytes: 1_110_000_000_000,
      purgeable_bytes: 0,
      is_system: false,
    },
  ],
};

const NOW_TS = Math.floor(Date.now() / 1000);

export const DEMO_HITS: ScanHit[] = [
  {
    id: "dev.cold_project_artifacts::/Users/dev/Projects/legacy-dashboard/node_modules",
    rule_id: "dev.cold_project_artifacts",
    category: "dev_ai",
    app_name: "Developer Toolchains & Local AI",
    app_name_zh: "开发者工具链与 AI 模型",
    title: "legacy-dashboard / node_modules (inactive > 30d)",
    title_zh: "legacy-dashboard / node_modules（超 30 天未活跃）",
    risk: "recreatable",
    default_checked: true,
    delete_mode: "permanent",
    requires_elevation: false,
    path: "/Users/dev/Projects/legacy-dashboard/node_modules",
    allocated_bytes: 2_840_000_000,
    file_count: 48_320,
    last_modified_ts: NOW_TS - 47 * 86_400,
    impact_note: "Source code & git history untouched. Run npm/pnpm install to restore.",
    impact_note_zh: "仅清理构建产物，源码与 Git 历史完好无损，下次开发时运行 npm install 即可恢复。",
    locked_by_process: null,
    native_command: null,
  },
  {
    id: "dev.cold_project_artifacts::/Users/dev/Projects/rust-wasm-demo/target",
    rule_id: "dev.cold_project_artifacts",
    category: "dev_ai",
    app_name: "Developer Toolchains & Local AI",
    app_name_zh: "开发者工具链与 AI 模型",
    title: "rust-wasm-demo / target (inactive > 30d)",
    title_zh: "rust-wasm-demo / target（超 30 天未活跃）",
    risk: "recreatable",
    default_checked: true,
    delete_mode: "permanent",
    requires_elevation: false,
    path: "/Users/dev/Projects/rust-wasm-demo/target",
    allocated_bytes: 6_420_000_000,
    file_count: 19_410,
    last_modified_ts: NOW_TS - 62 * 86_400,
    impact_note: "Cargo intermediate build artifacts; regenerated on cargo build.",
    impact_note_zh: "Rust 编译中间产物目录，下次运行 cargo build 时自动重建。",
    locked_by_process: null,
    native_command: null,
  },
  {
    id: "dev.xcode_derived_data::/Users/dev/Library/Developer/Xcode/DerivedData",
    rule_id: "dev.xcode_derived_data",
    category: "dev_ai",
    app_name: "Developer Toolchains & Local AI",
    app_name_zh: "开发者工具链与 AI 模型",
    title: "Xcode DerivedData & Simulator Caches",
    title_zh: "Xcode DerivedData 编译产物与模拟器缓存",
    risk: "recreatable",
    default_checked: true,
    delete_mode: "permanent",
    requires_elevation: false,
    path: "/Users/dev/Library/Developer/Xcode/DerivedData",
    allocated_bytes: 11_600_000_000,
    file_count: 82_150,
    last_modified_ts: NOW_TS - 12 * 86_400,
    impact_note: "Xcode regenerates index and build caches on next compile.",
    impact_note_zh: "安全清理 Xcode 中间编译产物与索引缓存，大幅释放 macOS 系统盘空间。",
    locked_by_process: null,
    native_command: null,
  },
  {
    id: "ai.huggingface_hub::/Users/dev/.cache/huggingface/hub/models--Qwen--Qwen2.5-7B-Instruct",
    rule_id: "ai.huggingface_hub",
    category: "dev_ai",
    app_name: "Developer Toolchains & Local AI",
    app_name_zh: "开发者工具链与 AI 模型",
    title: "HuggingFace Cache: Qwen/Qwen2.5-7B-Instruct",
    title_zh: "HuggingFace 缓存：Qwen/Qwen2.5-7B-Instruct",
    risk: "recreatable",
    default_checked: false,
    delete_mode: "trash",
    requires_elevation: false,
    path: "/Users/dev/.cache/huggingface/hub/models--Qwen--Qwen2.5-7B-Instruct",
    allocated_bytes: 14_300_000_000,
    file_count: 14,
    last_modified_ts: NOW_TS - 38 * 86_400,
    impact_note: "Cached model snapshots; re-downloading will be required if used again.",
    impact_note_zh: "清理 HuggingFace 本地模型快照缓存，再次推理时需重新拉取。",
    locked_by_process: null,
    native_command: null,
  },
  {
    id: "wechat.cache.thumbnails_and_temp::/Users/dev/Library/Containers/com.tencent.xinWeChat/Data/Library/Caches",
    rule_id: "wechat.cache.thumbnails_and_temp",
    category: "social_office",
    app_name: "Social & Office IM Apps",
    app_name_zh: "国民社交与办公软件",
    title: "WeChat Temporary & Thumbnail Cache",
    title_zh: "微信缩略图与临时运行缓存",
    risk: "safe",
    default_checked: true,
    delete_mode: "permanent",
    requires_elevation: false,
    path: "/Users/dev/Library/Containers/com.tencent.xinWeChat/Data/Library/Caches",
    allocated_bytes: 5_180_000_000,
    file_count: 27_940,
    last_modified_ts: NOW_TS - 5 * 86_400,
    impact_note: "Removes thumbnail & temp caches; strictly preserves chat databases and received documents.",
    impact_note_zh: "仅清理图片预览缩略图与临时缓存，严格排除聊天数据库与 FileStorage/File 个人文档。",
    locked_by_process: "WeChat",
    native_command: null,
  },
  {
    id: "feishu.cache.web_and_media::/Users/dev/Library/Caches/com.bytedance.feishu",
    rule_id: "feishu.cache.web_and_media",
    category: "social_office",
    app_name: "Social & Office IM Apps",
    app_name_zh: "国民社交与办公软件",
    title: "Feishu / Lark Cache",
    title_zh: "飞书（Feishu / Lark）运行与媒体缓存",
    risk: "safe",
    default_checked: true,
    delete_mode: "permanent",
    requires_elevation: false,
    path: "/Users/dev/Library/Caches/com.bytedance.feishu",
    allocated_bytes: 2_310_000_000,
    file_count: 9_840,
    last_modified_ts: NOW_TS - 8 * 86_400,
    impact_note: "Clears Feishu Chromium caches and historical logs.",
    impact_note_zh: "清理飞书桌面端网页缓存、GPU 缓存与历史日志。",
    locked_by_process: null,
    native_command: null,
  },
  {
    id: "browsers.chrome.cache::/Users/dev/Library/Caches/Google/Chrome/Default/Cache",
    rule_id: "browsers.chrome.cache",
    category: "browsers",
    app_name: "Web Browsers",
    app_name_zh: "主流浏览器缓存",
    title: "Google Chrome Web & GPU Cache",
    title_zh: "Chrome 网页与 GPU 缓存",
    risk: "safe",
    default_checked: true,
    delete_mode: "permanent",
    requires_elevation: false,
    path: "/Users/dev/Library/Caches/Google/Chrome/Default/Cache",
    allocated_bytes: 3_460_000_000,
    file_count: 14_520,
    last_modified_ts: NOW_TS - 1 * 86_400,
    impact_note: "Preserves cookies, passwords, bookmarks, and login sessions.",
    impact_note_zh: "严格保留 Cookie、登录态、书签与历史记录，仅清理网页静态与 GPU 缓存。",
    locked_by_process: "Google Chrome",
    native_command: null,
  },
  {
    id: "creative.jianying_capcut.cache::/Users/dev/Movies/JianyingPro/User Data/Cache",
    rule_id: "creative.jianying_capcut.cache",
    category: "creative_media",
    app_name: "Creative & Video Editing",
    app_name_zh: "影音剪辑与设计软件缓存",
    title: "Jianying Pro / CapCut Render & Proxy Cache",
    title_zh: "剪映 / CapCut 渲染代理与缓存",
    risk: "recreatable",
    default_checked: true,
    delete_mode: "permanent",
    requires_elevation: false,
    path: "/Users/dev/Movies/JianyingPro/User Data/Cache",
    allocated_bytes: 8_750_000_000,
    file_count: 1_290,
    last_modified_ts: NOW_TS - 19 * 86_400,
    impact_note: "Clears video proxy & render caches while strictly preserving draft project files.",
    impact_note_zh: "清理剪映渲染缓存与转码代理，严格保留所有工程草稿文件。",
    locked_by_process: null,
    native_command: null,
  },
  {
    id: "gaming.steam.cache::/Users/dev/Library/Application Support/Steam/steamapps/shadercache",
    rule_id: "gaming.steam.cache",
    category: "gaming",
    app_name: "Gaming Platforms & GPU Shaders",
    app_name_zh: "游戏平台与显卡着色器缓存",
    title: "Steam Depot, HTTP & Shader Caches",
    title_zh: "Steam 下载残留与着色器缓存",
    risk: "recreatable",
    default_checked: true,
    delete_mode: "permanent",
    requires_elevation: false,
    path: "/Users/dev/Library/Application Support/Steam/steamapps/shadercache",
    allocated_bytes: 4_120_000_000,
    file_count: 6_410,
    last_modified_ts: NOW_TS - 25 * 86_400,
    impact_note: "Removes stale compiled shader caches and depot staging residuals.",
    impact_note_zh: "清理 Steam 着色器缓存与旧版 depot 下载残留，不影响已安装游戏。",
    locked_by_process: null,
    native_command: null,
  },
  {
    id: "system.downloads_old_installers::/Users/dev/Downloads/Docker_Desktop_4.34.dmg",
    rule_id: "system.downloads_old_installers",
    category: "system",
    app_name: "Operating System Junk",
    app_name_zh: "操作系统临时与日志",
    title: "Old Installers in Downloads (>60d)",
    title_zh: "下载目录超 60 天旧安装包",
    risk: "review_required",
    default_checked: false,
    delete_mode: "trash",
    requires_elevation: false,
    path: "/Users/dev/Downloads/Docker_Desktop_4.34.dmg",
    allocated_bytes: 790_000_000,
    file_count: 1,
    last_modified_ts: NOW_TS - 94 * 86_400,
    impact_note: "Moves old .dmg installer to OS Trash (recoverable anytime).",
    impact_note_zh: "将超过 60 天未使用的安装包移入系统废纸篓，随时可还原。",
    locked_by_process: null,
    native_command: null,
  },
  {
    id: "ai.ollama_models::/Users/dev/.ollama/models/manifests/registry.ollama.ai/library/llama3.1/70b",
    rule_id: "ai.ollama_models",
    category: "dev_ai",
    app_name: "Developer Toolchains & Local AI",
    app_name_zh: "开发者工具链与 AI 模型",
    title: "Ollama Model: library/llama3.1/70b",
    title_zh: "Ollama 本地模型：library/llama3.1/70b",
    risk: "review_required",
    default_checked: false,
    delete_mode: "trash",
    requires_elevation: false,
    path: "/Users/dev/.ollama/models/manifests/registry.ollama.ai/library/llama3.1/70b",
    allocated_bytes: 39_800_000_000,
    file_count: 1,
    last_modified_ts: NOW_TS - 112 * 86_400,
    impact_note: "Review before removing multi-GB local LLM weights.",
    impact_note_zh: "本地大模型权重文件，请确认不再使用后移入废纸篓。",
    locked_by_process: null,
    native_command: null,
  },
];

export function buildDemoScanReport(categories: string[] | null): ScanReport {
  const hits = categories && categories.length > 0
    ? DEMO_HITS.filter((h) => categories.includes(h.category))
    : DEMO_HITS;
  let safe_bytes = 0;
  let recreatable_bytes = 0;
  let review_required_bytes = 0;
  let total_files = 0;
  for (const h of hits) {
    total_files += h.file_count;
    if (h.risk === "safe") safe_bytes += h.allocated_bytes;
    else if (h.risk === "recreatable") recreatable_bytes += h.allocated_bytes;
    else review_required_bytes += h.allocated_bytes;
  }
  return {
    platform: "macos",
    duration_ms: 412,
    total_reclaimable_bytes: safe_bytes + recreatable_bytes + review_required_bytes,
    total_files,
    skipped_warnings: 3,
    risk_summary: { safe_bytes, recreatable_bytes, review_required_bytes },
    categories: [],
    hits,
  };
}

const DEMO_LENS_ROOT: SpaceNode = {
  name: "dev (~)",
  path: "/Users/dev",
  allocated_bytes: 286_400_000_000,
  file_count: 412_980,
  is_dir: true,
  is_synthetic_other: false,
  children: [
    {
      name: "Library",
      path: "/Users/dev/Library",
      allocated_bytes: 112_800_000_000,
      file_count: 214_100,
      is_dir: true,
      is_synthetic_other: false,
      children: [
        {
          name: "Developer (Xcode)",
          path: "/Users/dev/Library/Developer",
          allocated_bytes: 54_200_000_000,
          file_count: 118_000,
          is_dir: true,
          is_synthetic_other: false,
          children: [],
        },
        {
          name: "Containers (WeChat)",
          path: "/Users/dev/Library/Containers",
          allocated_bytes: 34_600_000_000,
          file_count: 61_400,
          is_dir: true,
          is_synthetic_other: false,
          children: [],
        },
        {
          name: "Caches",
          path: "/Users/dev/Library/Caches",
          allocated_bytes: 24_000_000_000,
          file_count: 34_700,
          is_dir: true,
          is_synthetic_other: false,
          children: [],
        },
      ],
    },
    {
      name: ".ollama / models",
      path: "/Users/dev/.ollama",
      allocated_bytes: 68_400_000_000,
      file_count: 28,
      is_dir: true,
      is_synthetic_other: false,
      children: [],
    },
    {
      name: "Projects",
      path: "/Users/dev/Projects",
      allocated_bytes: 49_200_000_000,
      file_count: 168_200,
      is_dir: true,
      is_synthetic_other: false,
      children: [],
    },
    {
      name: "Movies (JianyingPro)",
      path: "/Users/dev/Movies",
      allocated_bytes: 31_700_000_000,
      file_count: 12_450,
      is_dir: true,
      is_synthetic_other: false,
      children: [],
    },
    {
      name: "Downloads",
      path: "/Users/dev/Downloads",
      allocated_bytes: 16_900_000_000,
      file_count: 420,
      is_dir: true,
      is_synthetic_other: false,
      children: [],
    },
    {
      name: "Other items",
      path: "/Users/dev",
      allocated_bytes: 7_400_000_000,
      file_count: 17_782,
      is_dir: false,
      is_synthetic_other: true,
      children: [],
    },
  ],
};

export const DEMO_LENS_REPORT: SpaceLensReport = {
  root: DEMO_LENS_ROOT,
  cold_files: [
    {
      path: "/Users/dev/Downloads/Ubuntu_24.04_arm64.iso",
      name: "Ubuntu_24.04_arm64.iso",
      allocated_bytes: 3_120_000_000,
      last_modified_ts: NOW_TS - 142 * 86_400,
      inactive_days: 142,
    },
    {
      path: "/Users/dev/Movies/RawFootage/A004_4K_ProRes.mov",
      name: "A004_4K_ProRes.mov",
      allocated_bytes: 6_840_000_000,
      last_modified_ts: NOW_TS - 118 * 86_400,
      inactive_days: 118,
    },
    {
      path: "/Users/dev/Downloads/Docker_Desktop_4.34.dmg",
      name: "Docker_Desktop_4.34.dmg",
      allocated_bytes: 790_000_000,
      last_modified_ts: NOW_TS - 94 * 86_400,
      inactive_days: 94,
    },
  ],
  duration_ms: 840,
  skipped_cloud_placeholders: 42,
  skipped_symlinks: 19,
  skipped_permission_errors: 0,
};

export const DEMO_RULES: RuleFile[] = [
  {
    schema_version: 1,
    category: "dev_ai",
    app_name: "Developer Toolchains & Local AI",
    app_name_zh: "开发者工具链与 AI 模型",
    rules: [
      {
        id: "dev.cold_project_artifacts",
        title: "Inactive Project Build Artifacts",
        title_zh: "冷门开发项目构建产物",
        kind: "smart_scanner",
        risk: "recreatable",
        default_checked: true,
        delete_mode: "permanent",
        impact_note: "Removes node_modules/target/.venv only for stale projects.",
        impact_note_zh: "仅清理长期未活跃项目的构建依赖目录，保留源码。",
      },
    ],
  },
];

export const DEMO_AUDIT: AuditRecord[] = [
  {
    timestamp: new Date(Date.now() - 86_400_000).toISOString(),
    rule_id: "browsers.chrome.cache",
    path: "/Users/dev/Library/Caches/Google/Chrome/Default/Cache",
    bytes_freed: 2_940_000_000,
    method: "permanent",
    success: true,
    note: null,
  },
  {
    timestamp: new Date(Date.now() - 172_800_000).toISOString(),
    rule_id: "system.downloads_old_installers",
    path: "/Users/dev/Downloads/Xcode_15.2.xip",
    bytes_freed: 7_420_000_000,
    method: "trash",
    success: true,
    note: null,
  },
];

export const DEMO_CONFIG: AppConfig = {
  ignore_paths: ["/Users/dev/Projects/pinned-client-repo"],
  workspace_roots: ["/Users/dev/Projects", "/Volumes/WorkSSD/Repos"],
  default_stale_days: 30,
};

export const DEMO_DUPLICATES: DuplicateReport = {
  duration_ms: 194,
  scanned_files: 18_420,
  candidate_files: 94,
  total_wasted_bytes: 4_820_000_000,
  skipped_hardlinks: 112,
  skipped_cloud_placeholders: 14,
  groups: [
    {
      blake3_hash: "8f3c91a4d7e02b6c9a5e1d4f7b8a3c21e0f4a5d6c7b8a90123456789abcdef01",
      file_size: 2_140_000_000,
      wasted_bytes: 4_280_000_000,
      entries: [
        {
          path: "/Users/dev/Movies/LaunchDemo_4K.mp4",
          name: "LaunchDemo_4K.mp4",
          allocated_bytes: 2_140_000_000,
          logical_bytes: 2_140_000_000,
          mtime_secs: NOW_TS - 80 * 86_400,
          recommended_keep: true,
        },
        {
          path: "/Users/dev/Downloads/LaunchDemo_4K (1).mp4",
          name: "LaunchDemo_4K (1).mp4",
          allocated_bytes: 2_140_000_000,
          logical_bytes: 2_140_000_000,
          mtime_secs: NOW_TS - 45 * 86_400,
          recommended_keep: false,
        },
        {
          path: "/Users/dev/Downloads/LaunchDemo_4K_copy.mp4",
          name: "LaunchDemo_4K_copy.mp4",
          allocated_bytes: 2_140_000_000,
          logical_bytes: 2_140_000_000,
          mtime_secs: NOW_TS - 12 * 86_400,
          recommended_keep: false,
        },
      ],
    },
    {
      blake3_hash: "2b4d6f8a0c1e3a5b7d9f11223344556677889900aabbccddeeff001122334455",
      file_size: 540_000_000,
      wasted_bytes: 540_000_000,
      entries: [
        {
          path: "/Users/dev/Archive/DesignSystem_v3.zip",
          name: "DesignSystem_v3.zip",
          allocated_bytes: 540_000_000,
          logical_bytes: 540_000_000,
          mtime_secs: NOW_TS - 120 * 86_400,
          recommended_keep: true,
        },
        {
          path: "/Users/dev/Downloads/DesignSystem_v3.zip",
          name: "DesignSystem_v3.zip",
          allocated_bytes: 540_000_000,
          logical_bytes: 540_000_000,
          mtime_secs: NOW_TS - 95 * 86_400,
          recommended_keep: false,
        },
      ],
    },
  ],
};

export const DEMO_UNINSTALLER: UninstallerReport = {
  platform: "macos",
  duration_ms: 162,
  total_orphan_bytes: 4_190_000_000,
  apps: [
    {
      name: "Figma",
      bundle_id: "com.figma.Desktop",
      install_path: "/Applications/Figma.app",
      app_bytes: 412_000_000,
      residue_bytes: 1_840_000_000,
      residues: [
        {
          path: "/Users/dev/Library/Application Support/Figma",
          kind: "Application Support",
          allocated_bytes: 1_420_000_000,
          file_count: 14_210,
        },
        {
          path: "/Users/dev/Library/Caches/com.figma.Desktop",
          kind: "Caches",
          allocated_bytes: 420_000_000,
          file_count: 2_310,
        },
      ],
    },
  ],
  orphans: [
    {
      name: "com.oldvendor.LegacyVideoSuite",
      path: "/Users/dev/Library/Application Support/com.oldvendor.LegacyVideoSuite",
      location_kind: "Application Support",
      allocated_bytes: 2_980_000_000,
      file_count: 4_820,
      last_modified_ts: NOW_TS - 160 * 86_400,
      inactive_days: 160,
    },
    {
      name: "com.removed.ScreenRecorderPro",
      path: "/Users/dev/Library/Caches/com.removed.ScreenRecorderPro",
      location_kind: "Caches",
      allocated_bytes: 1_210_000_000,
      file_count: 680,
      last_modified_ts: NOW_TS - 92 * 86_400,
      inactive_days: 92,
    },
  ],
};

export const DEMO_VDISKS: VirtualDiskReport = {
  platform: "macos",
  duration_ms: 14,
  total_allocated_bytes: 29_400_000_000,
  total_logical_bytes: 68_719_476_736,
  disks: [
    {
      id: "vdisk::/Users/dev/Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw",
      kind: "docker_desktop_raw_mac",
      name: "Docker Desktop (Docker.raw)",
      path: "/Users/dev/Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw",
      allocated_bytes: 29_400_000_000,
      logical_bytes: 68_719_476_736,
      sparse_savings_bytes: 39_319_476_736,
      is_in_use: true,
      requires_elevation: false,
      compact_command: "docker builder prune -af && docker image prune -f",
      compact_script:
        "# Reclaim unused build cache & layers inside Docker VM\ndocker builder prune -af\ndocker image prune -f",
      safety_note:
        "APFS stores Docker.raw as a sparse file; prune via Docker CLI instead of deleting the raw VM image.",
      safety_note_zh:
        "macOS APFS 以稀疏文件存储 Docker.raw，真实 SSD 占用小于逻辑上限；请通过 Docker CLI 回收内部空间。",
    },
  ],
};

export async function bridgeInvoke<T>(
  cmd: string,
  args?: Record<string, unknown>
): Promise<T> {
  if (isTauriRuntime()) {
    return invoke<T>(cmd, args);
  }

  switch (cmd) {
    case "get_disk_overview":
      return DEMO_OVERVIEW as T;
    case "get_app_config":
      return DEMO_CONFIG as T;
    case "get_audit_history":
      return DEMO_AUDIT as T;
    case "get_builtin_rules":
      return DEMO_RULES as T;
    case "start_rule_scan":
      return buildDemoScanReport((args?.categories as string[] | null) ?? null) as T;
    case "start_space_lens":
      return DEMO_LENS_REPORT as T;
    case "start_duplicate_scan":
      return DEMO_DUPLICATES as T;
    case "clean_duplicate_groups": {
      const groups = (args?.groups as DuplicateCleanGroup[]) ?? [];
      const count = groups.reduce((acc, g) => acc + g.delete_paths.length, 0);
      return {
        dry_run: Boolean(args?.dryRun),
        duration_ms: 48,
        total_freed_bytes: count * 512_000_000,
        succeeded_count: count,
        failed_count: 0,
        outcomes: [],
      } as T;
    }
    case "scan_uninstaller":
      return DEMO_UNINSTALLER as T;
    case "clean_orphans":
    case "uninstall_app": {
      const paths = (args?.paths as string[]) ?? [];
      return {
        dry_run: Boolean(args?.dryRun),
        duration_ms: 52,
        total_freed_bytes: paths.length * 1_000_000_000,
        succeeded_count: paths.length,
        failed_count: 0,
        outcomes: [],
      } as T;
    }
    case "run_clean": {
      const items = (args?.items as CleanItemRequest[]) ?? [];
      const dryRun = Boolean(args?.dryRun);
      const report: CleanReport = {
        dry_run: dryRun,
        duration_ms: 85,
        total_freed_bytes: items.length * 1_024_000,
        succeeded_count: items.length,
        failed_count: 0,
        outcomes: items.map((it) => ({
          rule_id: it.rule_id,
          path: it.path,
          actual_mode: it.risk === "review_required" ? "trash" : it.delete_mode,
          freed_bytes: 1_024_000,
          success: true,
          error: null,
        })),
      };
      return report as T;
    }
    case "update_workspace_roots":
    case "update_ignore_list":
      return DEMO_CONFIG as T;
    case "thin_local_snapshots":
      return "[dry-run] tmutil thinlocalsnapshots / 10737418240 4" as T;
    case "scan_virtual_disks":
      return DEMO_VDISKS as T;
    case "cancel_scan":
    case "reveal_in_folder":
    case "open_fda_settings":
      return undefined as T;
    default:
      throw new Error(`Unknown command in demo bridge: ${cmd}`);
  }
}

export function createProgressChannel(
  handler: (ev: ScanProgressEvent) => void
): Channel<ScanProgressEvent> {
  if (isTauriRuntime()) {
    const ch = new Channel<ScanProgressEvent>();
    ch.onmessage = handler;
    return ch;
  }
  return { onmessage: handler } as Channel<ScanProgressEvent>;
}
