#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use clap::{Parser, Subcommand};
use clearlens_core::{
    clean_duplicates, clean_orphan_paths, execute_clean_with_elevation, load_all_rules,
    load_app_config, platform, read_audit_history, run_elevation_worker_files, run_rule_scan,
    scan_apps_and_orphans, scan_duplicates, scan_space_lens, scan_virtual_disks,
    update_ignore_list, update_workspace_roots, validate_toml_str, CleanItemRequest,
    DuplicateCleanGroup, RiskLevel, ScanOptions, ScanProgressEvent, TargetPlatform,
};
use comfy_table::{presets::UTF8_FULL, Table};
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "clens",
    version,
    about = "ClearLens — Transparent cross-platform disk cleaner, duplicate finder & Space Lens CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show disk volumes, physical free space, APFS purgeable space, and rule status
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Scan system, browsers, dev/AI, IM, creative, and gaming caches (read-only)
    Scan {
        #[arg(long, default_value = "smart")]
        mode: String,
        #[arg(long)]
        category: Option<String>,
        #[arg(long, default_value_t = 30)]
        stale_days: u32,
        #[arg(long = "workspace-root")]
        workspace_roots: Vec<PathBuf>,
        #[arg(long = "simulate-os")]
        simulate_os: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Clean matched items (defaults to --dry-run unless --apply is explicitly passed)
    Clean {
        #[arg(long, default_value = "safe")]
        risk: String,
        #[arg(long)]
        category: Option<String>,
        #[arg(long = "rule")]
        rule_filter: Option<String>,
        #[arg(long = "match-path")]
        match_path: Option<String>,
        #[arg(long, default_value_t = 30)]
        stale_days: u32,
        #[arg(long = "workspace-root")]
        workspace_roots: Vec<PathBuf>,
        #[arg(long = "simulate-os")]
        simulate_os: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        json: bool,
    },
    /// Analyze directory physical sizes & find large cold files
    Lens {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long, default_value_t = 100)]
        min_size_mb: u64,
        #[arg(long, default_value_t = 90)]
        cold_days: u32,
        #[arg(long)]
        json: bool,
    },
    /// Find exact duplicate files using the 3-stage BLAKE3 funnel (hardlink & cloud-safe)
    Duplicates {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long, default_value_t = 1024)]
        min_size_kb: u64,
        #[arg(long)]
        json: bool,
    },
    /// Safely clean redundant duplicate copies into OS Trash (always keeps >= 1 original copy)
    DuplicatesClean {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long, default_value_t = 1024)]
        min_size_kb: u64,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        json: bool,
    },
    /// Inspect installed apps and their associated cache/config residues
    Apps {
        #[arg(long = "simulate-os")]
        simulate_os: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Detect & optionally clean stale orphan app residues left by previously uninstalled apps
    Orphans {
        #[arg(long = "simulate-os")]
        simulate_os: Option<String>,
        #[arg(long, default_value_t = 14)]
        min_age_days: u32,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        json: bool,
    },
    /// Inspect WSL2 (.vhdx), Docker (Docker.raw), OrbStack & Lima virtual disks with safe compaction guides
    Vdisks {
        #[arg(long = "simulate-os")]
        simulate_os: Option<String>,
        #[arg(long)]
        show_script: bool,
        #[arg(long)]
        json: bool,
    },
    /// Manage persisted workspace roots and ignore whitelist (~/.clearlens/config.json)
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// List or validate TOML rule packs
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
    /// Show recent cleanup audit history
    Audit {
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Internal one-shot elevated worker entry point (invoked via on-demand UAC/sudo)
    #[command(hide = true)]
    ElevatedWorker {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        response: PathBuf,
    },
}

#[derive(Subcommand)]
enum RulesAction {
    List,
    Validate { path: Option<PathBuf> },
}

#[derive(Subcommand)]
enum ConfigAction {
    Show,
    AddWorkspace { path: PathBuf },
    RemoveWorkspace { path: PathBuf },
    AddIgnore { path: PathBuf },
    RemoveIgnore { path: PathBuf },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Commands::Status { json } => {
            let rules = load_all_rules()?;
            let rule_count: usize = rules.iter().map(|r| r.rules.len()).sum();
            let overview = platform::get_disk_overview(rule_count);
            if json {
                println!("{}", serde_json::to_string_pretty(&overview).unwrap());
            } else {
                println!("ClearLens v{} Status ({:?})", env!("CARGO_PKG_VERSION"), overview.platform);
                println!("  Mount Point      : {}", overview.mount_point);
                println!("  Total Capacity   : {}", format_bytes(overview.total_bytes));
                println!("  Physical Free    : {}", format_bytes(overview.available_bytes));
                if overview.purgeable_bytes > 0 {
                    println!(
                        "  APFS Purgeable   : {}",
                        format_bytes(overview.purgeable_bytes)
                    );
                }
                if overview.local_snapshots_count > 0 {
                    println!("  Local Snapshots  : {}", overview.local_snapshots_count);
                }
                println!(
                    "  Full Disk Access : {}",
                    if overview.fda_granted { "Granted" } else { "Not Granted" }
                );
                println!("  Allocator        : {}", active_allocator_name());
                println!("  Loaded Rules     : {}", overview.rule_count);
                if !overview.volumes.is_empty() {
                    println!("  Detected Volumes : {}", overview.volumes.len());
                    for v in &overview.volumes {
                        println!(
                            "    - {} ({}) Free: {} / Total: {}",
                            v.label,
                            v.mount_point,
                            format_bytes(v.available_bytes),
                            format_bytes(v.total_bytes)
                        );
                    }
                }
            }
        }
        Commands::Scan {
            mode,
            category,
            stale_days,
            workspace_roots,
            simulate_os,
            json,
        } => {
            let platform = resolve_platform(simulate_os)?;
            let cfg = load_app_config();
            let categories = category.map(|c| {
                c.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            });
            let roots: Vec<PathBuf> = if workspace_roots.is_empty() {
                cfg.workspace_roots
            } else {
                workspace_roots
                    .into_iter()
                    .map(|p| clearlens_core::config::normalize_user_path(&p))
                    .collect()
            };

            let spinner = make_spinner(!json, "Scanning disk caches & artifacts...");
            let cancel = AtomicBool::new(false);
            let opts = ScanOptions {
                platform,
                categories,
                stale_days,
                workspace_roots: roots,
                ignore_paths: cfg.ignore_paths,
            };
            let report = run_rule_scan(&opts, &cancel, |ev| {
                if let (Some(sp), ScanProgressEvent::RuleMatched { rule_id, .. }) = (&spinner, ev) {
                    sp.set_message(format!("Matched: {rule_id}"));
                }
            })?;
            if let Some(sp) = spinner {
                sp.finish_and_clear();
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                let mut table = Table::new();
                table.load_style(UTF8_FULL);
                table.set_header(vec!["Risk", "Rule ID", "Size", "Files", "Target Path"]);

                let show_all = mode == "all";
                for h in &report.hits {
                    if !show_all && h.risk == RiskLevel::ReviewRequired && h.allocated_bytes == 0 {
                        continue;
                    }
                    table.add_row(vec![
                        risk_badge(h.risk).to_string(),
                        h.rule_id.clone(),
                        format_bytes(h.allocated_bytes),
                        h.file_count.to_string(),
                        h.path.display().to_string(),
                    ]);
                }

                println!("{table}");
                println!(
                    "\nSummary ({:?}, {} ms): Total Reclaimable = {} (Safe: {}, Recreatable: {}, Review: {})",
                    report.platform,
                    report.duration_ms,
                    format_bytes(report.total_reclaimable_bytes),
                    format_bytes(report.risk_summary.safe_bytes),
                    format_bytes(report.risk_summary.recreatable_bytes),
                    format_bytes(report.risk_summary.review_required_bytes)
                );
            }
        }
        Commands::Clean {
            risk,
            category,
            rule_filter,
            match_path,
            stale_days,
            workspace_roots,
            simulate_os,
            dry_run,
            apply,
            json,
        } => {
            let platform = resolve_platform(simulate_os)?;
            let is_dry_run = !apply || dry_run;
            let allowed_risks: Vec<RiskLevel> = risk
                .split(',')
                .filter_map(|r| match r.trim() {
                    "safe" => Some(RiskLevel::Safe),
                    "recreatable" => Some(RiskLevel::Recreatable),
                    "review_required" => Some(RiskLevel::ReviewRequired),
                    _ => None,
                })
                .collect();
            if allowed_risks.is_empty() {
                return Err("no valid --risk levels specified (use safe,recreatable,review_required)".into());
            }

            let cfg = load_app_config();
            let categories = category.map(|c| {
                c.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            });
            let opts = ScanOptions {
                platform,
                categories,
                stale_days,
                workspace_roots: if workspace_roots.is_empty() {
                    cfg.workspace_roots
                } else {
                    workspace_roots
                        .into_iter()
                        .map(|p| clearlens_core::config::normalize_user_path(&p))
                        .collect()
                },
                ignore_paths: cfg.ignore_paths,
            };

            let cancel = AtomicBool::new(false);
            let scan_report = run_rule_scan(&opts, &cancel, |_| {})?;
            let requests: Vec<CleanItemRequest> = scan_report
                .hits
                .into_iter()
                .filter(|h| allowed_risks.contains(&h.risk))
                .filter(|h| {
                    rule_filter
                        .as_ref()
                        .map(|rf| h.rule_id == *rf)
                        .unwrap_or(true)
                })
                .filter(|h| {
                    match_path
                        .as_ref()
                        .map(|mp| h.path.to_string_lossy().contains(mp))
                        .unwrap_or(true)
                })
                .map(|h| CleanItemRequest {
                    rule_id: h.rule_id,
                    path: h.path,
                    risk: h.risk,
                    delete_mode: h.delete_mode,
                    native_command: h.native_command,
                })
                .collect();

            let clean_report = execute_clean_with_elevation(&requests, is_dry_run);
            print_clean_report(&clean_report, is_dry_run, json);
        }
        Commands::Lens {
            path,
            min_size_mb,
            cold_days,
            json,
        } => {
            let cancel = AtomicBool::new(false);
            let norm_path = clearlens_core::config::normalize_user_path(&path);
            let spinner = make_spinner(!json, "Analyzing physical disk allocation...");
            let report = scan_space_lens(
                &norm_path,
                min_size_mb * 1_048_576,
                cold_days,
                &cancel,
                |_| {},
            )?;
            if let Some(sp) = spinner {
                sp.finish_and_clear();
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                println!(
                    "Space Lens: {} (Physical Allocated: {}, Files: {}, Time: {} ms)",
                    report.root.path.display(),
                    format_bytes(report.root.allocated_bytes),
                    report.root.file_count,
                    report.duration_ms
                );
                let mut table = Table::new();
                table.load_style(UTF8_FULL);
                table.set_header(vec!["Name", "Type", "Physical Size", "Files"]);
                for ch in report.root.children.iter().take(20) {
                    table.add_row(vec![
                        ch.name.clone(),
                        (if ch.is_dir { "Dir" } else { "File" }).to_string(),
                        format_bytes(ch.allocated_bytes),
                        ch.file_count.to_string(),
                    ]);
                }
                println!("{table}");
                if !report.cold_files.is_empty() {
                    println!("\nCold & Large Files ({}):", report.cold_files.len());
                    for cf in report.cold_files.iter().take(10) {
                        println!(
                            "  - {} ({} | inactive {}d)",
                            cf.path.display(),
                            format_bytes(cf.allocated_bytes),
                            cf.inactive_days
                        );
                    }
                }
            }
        }
        Commands::Duplicates {
            path,
            min_size_kb,
            json,
        } => {
            let cancel = AtomicBool::new(false);
            let norm_path = clearlens_core::config::normalize_user_path(&path);
            let spinner = make_spinner(!json, "Scanning duplicates with 3-stage BLAKE3 funnel...");
            let report = scan_duplicates(&[norm_path], min_size_kb * 1024, &cancel, |_| {})?;
            if let Some(sp) = spinner {
                sp.finish_and_clear();
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                println!(
                    "Duplicate Finder ({} ms): {} groups, Wasted = {} (Hardlinks skipped: {})",
                    report.duration_ms,
                    report.groups.len(),
                    format_bytes(report.total_wasted_bytes),
                    report.skipped_hardlinks
                );
                for g in &report.groups {
                    println!(
                        "\n  Group {} ({} each, {} wasted):",
                        &g.blake3_hash[..12],
                        format_bytes(g.file_size),
                        format_bytes(g.wasted_bytes)
                    );
                    for e in &g.entries {
                        println!(
                            "    [{}] {}",
                            if e.recommended_keep { "KEEP" } else { "COPY" },
                            e.path.display()
                        );
                    }
                }
            }
        }
        Commands::DuplicatesClean {
            path,
            min_size_kb,
            dry_run,
            apply,
            json,
        } => {
            let is_dry_run = !apply || dry_run;
            let cancel = AtomicBool::new(false);
            let norm_path = clearlens_core::config::normalize_user_path(&path);
            let report = scan_duplicates(&[norm_path], min_size_kb * 1024, &cancel, |_| {})?;
            let groups: Vec<DuplicateCleanGroup> = report
                .groups
                .into_iter()
                .map(|g| {
                    let all_paths: Vec<PathBuf> = g.entries.iter().map(|e| e.path.clone()).collect();
                    let delete_paths: Vec<PathBuf> = g
                        .entries
                        .into_iter()
                        .filter(|e| !e.recommended_keep)
                        .map(|e| e.path)
                        .collect();
                    DuplicateCleanGroup {
                        blake3_hash: g.blake3_hash,
                        all_paths,
                        delete_paths,
                    }
                })
                .collect();
            let clean_res = clean_duplicates(&groups, is_dry_run)?;
            print_clean_report(&clean_res, is_dry_run, json);
        }
        Commands::Apps { simulate_os, json } => {
            let platform = resolve_platform(simulate_os)?;
            let cancel = AtomicBool::new(false);
            let report = scan_apps_and_orphans(platform, 14, &cancel)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                let mut table = Table::new();
                table.load_style(UTF8_FULL);
                table.set_header(vec!["App Name", "Bundle ID", "App Size", "Residue Size", "Residues"]);
                for app in &report.apps {
                    table.add_row(vec![
                        app.name.clone(),
                        app.bundle_id.clone().unwrap_or_else(|| "-".into()),
                        format_bytes(app.app_bytes),
                        format_bytes(app.residue_bytes),
                        app.residues.len().to_string(),
                    ]);
                }
                println!("{table}");
            }
        }
        Commands::Orphans {
            simulate_os,
            min_age_days,
            dry_run,
            apply,
            json,
        } => {
            let platform = resolve_platform(simulate_os)?;
            let cancel = AtomicBool::new(false);
            let report = scan_apps_and_orphans(platform, min_age_days, &cancel)?;
            if apply && !dry_run {
                let paths: Vec<PathBuf> = report.orphans.iter().map(|o| o.path.clone()).collect();
                let res = clean_orphan_paths(&paths, false);
                print_clean_report(&res, false, json);
            } else if json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                let mut table = Table::new();
                table.load_style(UTF8_FULL);
                table.set_header(vec!["Orphan Name", "Location", "Inactive", "Size", "Path"]);
                for o in &report.orphans {
                    table.add_row(vec![
                        o.name.clone(),
                        o.location_kind.clone(),
                        format!("{}d", o.inactive_days),
                        format_bytes(o.allocated_bytes),
                        o.path.display().to_string(),
                    ]);
                }
                println!("{table}");
                println!(
                    "\nOrphan Residue Total: {} ({} items). Pass --apply to move to OS Trash.",
                    format_bytes(report.total_orphan_bytes),
                    report.orphans.len()
                );
            }
        }
        Commands::Vdisks {
            simulate_os,
            show_script,
            json,
        } => {
            let platform = resolve_platform(simulate_os)?;
            let report = scan_virtual_disks(platform);
            if json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else if report.disks.is_empty() {
                println!("No WSL2 / Docker / OrbStack / Lima virtual disks detected.");
            } else {
                let mut table = Table::new();
                table.load_style(UTF8_FULL);
                table.set_header(vec![
                    "Virtual Disk",
                    "Physical SSD",
                    "Virtual Ceiling",
                    "In Use",
                    "Path",
                ]);
                for d in &report.disks {
                    table.add_row(vec![
                        d.name.clone(),
                        format_bytes(d.allocated_bytes),
                        format_bytes(d.logical_bytes),
                        if d.is_in_use { "YES" } else { "No" }.to_string(),
                        d.path.display().to_string(),
                    ]);
                }
                println!("{table}");
                println!(
                    "\nTotal Physical Allocated: {} (Virtual Logical Ceiling: {})",
                    format_bytes(report.total_allocated_bytes),
                    format_bytes(report.total_logical_bytes)
                );
                if show_script {
                    for d in &report.disks {
                        println!("\n--- Safe Compaction Script for {} ---\n{}\n", d.name, d.compact_script);
                    }
                } else {
                    println!("Tip: Pass --show-script to print copyable safe compaction commands.");
                }
            }
        }
        Commands::Config { action } => match action {
            ConfigAction::Show => {
                let cfg = load_app_config();
                println!("{}", serde_json::to_string_pretty(&cfg).unwrap());
            }
            ConfigAction::AddWorkspace { path } => {
                let cfg = update_workspace_roots(path, false).map_err(|e| e.to_string())?;
                println!("Workspace roots ({}): {:?}", cfg.workspace_roots.len(), cfg.workspace_roots);
            }
            ConfigAction::RemoveWorkspace { path } => {
                let cfg = update_workspace_roots(path, true).map_err(|e| e.to_string())?;
                println!("Workspace roots ({}): {:?}", cfg.workspace_roots.len(), cfg.workspace_roots);
            }
            ConfigAction::AddIgnore { path } => {
                let cfg = update_ignore_list(path, false).map_err(|e| e.to_string())?;
                println!("Ignore paths ({}): {:?}", cfg.ignore_paths.len(), cfg.ignore_paths);
            }
            ConfigAction::RemoveIgnore { path } => {
                let cfg = update_ignore_list(path, true).map_err(|e| e.to_string())?;
                println!("Ignore paths ({}): {:?}", cfg.ignore_paths.len(), cfg.ignore_paths);
            }
        },
        Commands::Rules { action } => match action {
            RulesAction::List => {
                let files = load_all_rules()?;
                let mut table = Table::new();
                table.load_style(UTF8_FULL);
                table.set_header(vec!["Category", "Rule ID", "Risk", "Mode", "Title"]);
                for rf in files {
                    for r in rf.rules {
                        table.add_row(vec![
                            rf.category.clone(),
                            r.id,
                            risk_badge(r.risk).to_string(),
                            format!("{:?}", r.delete_mode),
                            r.title,
                        ]);
                    }
                }
                println!("{table}");
            }
            RulesAction::Validate { path } => {
                if let Some(p) = path {
                    let raw = fs::read_to_string(&p)
                        .map_err(|e| format!("failed to read {}: {e}", p.display()))?;
                    let rf = validate_toml_str(&raw)?;
                    println!(
                        "VALID: {} ({} rules in category '{}')",
                        p.display(),
                        rf.rules.len(),
                        rf.category
                    );
                } else {
                    let files = load_all_rules()?;
                    let count: usize = files.iter().map(|f| f.rules.len()).sum();
                    println!(
                        "VALID: {} rule packs ({} rules) passed safety blocklist checks.",
                        files.len(),
                        count
                    );
                }
            }
        },
        Commands::Audit { limit, json } => {
            let records = read_audit_history(limit);
            if json {
                println!("{}", serde_json::to_string_pretty(&records).unwrap());
            } else if records.is_empty() {
                println!("No cleanup audit records yet.");
            } else {
                for r in records {
                    println!(
                        "{} | {} | {} | {} | {}",
                        r.timestamp,
                        r.method,
                        r.rule_id,
                        format_bytes(r.bytes_freed),
                        r.path.display()
                    );
                }
            }
        }
        Commands::ElevatedWorker { request, response } => {
            let res = run_elevation_worker_files(&request, &response)?;
            if !res.success {
                return Err(res.message);
            }
        }
    }
    Ok(())
}

fn print_clean_report(clean_report: &clearlens_core::CleanReport, is_dry_run: bool, json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(clean_report).unwrap());
    } else {
        println!(
            "{} Clean Result: {} succeeded, {} failed, Freed = {}",
            if is_dry_run { "[DRY-RUN]" } else { "[APPLIED]" },
            clean_report.succeeded_count,
            clean_report.failed_count,
            format_bytes(clean_report.total_freed_bytes)
        );
        for o in &clean_report.outcomes {
            println!(
                "  - [{}] {:?} {} ({})",
                if o.success { "OK" } else { "ERR" },
                o.actual_mode,
                o.path.display(),
                format_bytes(o.freed_bytes)
            );
        }
    }
}

fn resolve_platform(sim: Option<String>) -> Result<TargetPlatform, String> {
    match sim {
        Some(s) => TargetPlatform::from_str_opt(&s)
            .ok_or_else(|| format!("unknown --simulate-os '{s}' (use macos, windows, or linux)")),
        None => Ok(TargetPlatform::current()),
    }
}

fn risk_badge(risk: RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Safe => "SAFE",
        RiskLevel::Recreatable => "RECREATABLE",
        RiskLevel::ReviewRequired => "REVIEW",
    }
}

fn make_spinner(enabled: bool, msg: &str) -> Option<ProgressBar> {
    if !enabled {
        return None;
    }
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .unwrap()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    Some(pb)
}

fn active_allocator_name() -> &'static str {
    if cfg!(feature = "mimalloc") {
        "mimalloc"
    } else {
        "system"
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut val = bytes as f64;
    let mut idx = 0;
    while val >= 1024.0 && idx < UNITS.len() - 1 {
        val /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{bytes} B")
    } else {
        format!("{val:.2} {}", UNITS[idx])
    }
}
