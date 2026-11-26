# Changelog

All notable changes to ClearLens will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-11-26

### Fixed
- **Duplicate Finder (`duplicates.rs`)**: Deterministically sort directory traversal entries before hardlink `(dev, ino)` deduplication so non-transient, shorter-named originals are consistently retained across `ext4`, `overlayfs`, `APFS`, and `NTFS`.
- **Windows Cloud Placeholder Safety (`platform/windows.rs`)**: Detect `.icloud` stub placeholder filenames in `inspect_path_meta_windows` in addition to NTFS `OFFLINE` / `RECALL_ON_*` attributes.
- **Cross-Platform CI & Test Suite**:
  - Punch APFS sparse holes via `F_PUNCHHOLE` in the macOS virtual disk sparse test so APFS physical vs. logical allocation is verified accurately.
  - Prevent cascading mutex `PoisonError` across isolated test runs and isolate `USERPROFILE` / `LOCALAPPDATA` / `APPDATA` / `CLEARLENS_TRASH_DIR` across macOS, Linux, and Windows runners.
  - Enable `fail-fast: false` in CI matrix and group Dependabot updates monthly to reduce PR noise.

## [0.1.0] - 2026-11-26

### Added
- **Core Engine (`clearlens-core`)**:
  - Cross-platform scanner supporting macOS (`SF_DATALESS`, APFS Purgeable space, Full Disk Access detection, multi-volume enumeration) and Windows (`GetCompressedFileSizeW`, NTFS reparse/mount-point & offline recall guards, `GetFileInformationByHandle` hardlink deduplication, `GetLogicalDrives`).
  - Hardened safety guardrail pipeline: engine-hardcoded `ProtectedBlocklist` (OS roots, `.ssh`/`.gnupg`/`.aws`/`.kube`/`.azure`/`.git`/`.npmrc`/`.docker/config.json`/browser secrets/virtual disk images), symlink/reparse/cross-mount isolation (`xdev`), cloud placeholder skip, 32-shard hardlink deduplication, normalized cross-platform `ignore_paths`, and `sysinfo` active process lock check.
  - Hybrid rule engine combining 39 declarative TOML glob rules across 6 packs (System, Web Browsers, Dev & Local AI, IM & Office, Creative Media, Gaming/GPU Shaders) with built-in Rust smart scanners (`cold_project_artifacts`, `ollama_models`, `huggingface_hub`, `docker_system_df`).
  - **Ollama Reference-Counted Blob GC** (`rules/ollama_gc.rs`): computes global manifest digest reference counts and safely moves only `ref_count == 1` exclusive blobs alongside the removed manifest into OS Trash while preserving shared base layers.
  - **Space Lens & Cold File Radar** (`lens.rs`): parallel physical block accounting, depth-4+ infinite drilldown (`has_more_children`), 100ms throttled live progress streaming, and 60fps Canvas Squarified Treemap.
  - **BLAKE3 3-Stage Duplicate Finder** (`duplicates.rs`): exact size -> 4KB head+tail pre-hash -> full streaming BLAKE3 verification with hardlink exclusion and engine-enforced Anti-Wipe Safety Lock (including clean-time BLAKE3 survivor TOCTOU verification).
  - **App Uninstaller & Orphan Residue Hunter** (`uninstaller.rs`): cross-platform app bundle & residue discovery with system/self-uninstall allowlist guards and stale unowned orphan detection.
  - **WSL2 / Docker Virtual Disk Compaction Inspector** (`vdisk.rs`): inspects `.vhdx`, `Docker.raw`, OrbStack `data.img`, and Lima/Colima `diffdisk` non-destructively and generates copyable safe compaction scripts.
  - **On-Demand Elevation Worker Protocol** (`elevation.rs` + `elevated-worker`), risk-routed deletion (`review_required` forced to OS Trash), private (`0o700`/`0o600`) config/JSONL audit log (`~/.clearlens/audit.jsonl`), and `mimalloc` global allocator.
- **CLI (`clens`) & Desktop GUI (`apps/desktop`)**:
  - `clens`: `status`, `scan`, `clean` (safe `--dry-run` default), `lens`, `duplicates`, `duplicates-clean`, `apps`, `orphans`, `vdisks`, `config`, `rules list/validate`, and `audit`.
  - Tauri v2 + React + TypeScript + Tailwind CSS dual-mode UI (`Smart` & `Pro Inspector`), Dry-Run preview modal, interactive Treemap, EN/ZH-CN i18n, Light/Dark themes, and domain-isolated Tauri IPC allowlists.
- **CI, Packaging & Isolated Docker Verification**:
  - Multi-stage Docker test (`docker/Dockerfile.test`), `.deb`/`.tar.gz` packaging + clean Debian install cleanup E2E (`docker/Dockerfile.package-install`), Windows workspace cross-check (`docker/Dockerfile.cross-check`), and GitHub Actions Win/Mac installer release workflows.
