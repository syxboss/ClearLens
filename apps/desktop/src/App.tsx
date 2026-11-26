import React, { useEffect, useMemo, useState } from "react";
import {
  bridgeInvoke,
  buildDemoScanReport,
  createProgressChannel,
  DEMO_DUPLICATES,
  DEMO_LENS_REPORT,
  DEMO_UNINSTALLER,
  DEMO_VDISKS,
  isTauriRuntime,
} from "./api/bridge";
import {
  CircleCheck,
  CircleX,
  ChevronRight,
  Copy,
  Eye,
  FileSearch,
  FolderOpen,
  HardDrive,
  History,
  Languages,
  Layers,
  Moon,
  PackageX,
  Plus,
  RefreshCw,
  ShieldCheck,
  Sun,
  Trash2,
  TriangleAlert,
  X,
} from "lucide-react";
import { TreemapCanvas } from "./components/TreemapCanvas";
import { MESSAGES, type Locale, type MessageKey } from "./i18n";
import type {
  AppConfig,
  AuditRecord,
  CleanItemRequest,
  CleanReport,
  DiskOverview,
  DuplicateCleanGroup,
  DuplicateReport,
  RiskLevel,
  RuleFile,
  ScanHit,
  ScanReport,
  SpaceLensReport,
  SpaceNode,
  UninstallerReport,
  VirtualDiskReport,
} from "./types";
import {
  computeDefaultSelectedIds,
  formatBytes,
  toggleDuplicateDeletion,
} from "./utils/treemap";

type NavTab = "smart" | "deep" | "lens" | "duplicates" | "uninstaller" | "audit";
type AuditSubTab = "history" | "settings" | "ignore" | "rules";
type UninstSubTab = "orphans" | "apps";

function getInitialQueryState() {
  if (typeof window === "undefined") {
    return {
      locale: "zh-CN" as Locale,
      dark: true,
      tab: "smart" as NavTab,
      proMode: false,
      cat: "all",
    };
  }
  const params = new URLSearchParams(window.location.search);
  const langParam = params.get("lang");
  const tabParam = params.get("tab");
  const themeParam = params.get("theme");
  const proParam = params.get("pro");
  const catParam = params.get("cat");

  return {
    locale: (langParam === "en" ? "en" : "zh-CN") as Locale,
    dark: themeParam !== "light",
    tab: ([
      "smart",
      "deep",
      "lens",
      "duplicates",
      "uninstaller",
      "audit",
    ].includes(tabParam ?? "")
      ? tabParam
      : "smart") as NavTab,
    proMode: proParam === "1" || proParam === "true",
    cat: catParam ?? "all",
  };
}

export function App() {
  const initial = useMemo(() => getInitialQueryState(), []);
  const [locale, setLocale] = useState<Locale>(initial.locale);
  const [dark, setDark] = useState<boolean>(initial.dark);
  const [tab, setTab] = useState<NavTab>(initial.tab);
  const [proMode, setProMode] = useState<boolean>(initial.proMode);

  const [overview, setOverview] = useState<DiskOverview | null>(null);
  const [scanReport, setScanReport] = useState<ScanReport | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanStatusText, setScanStatusText] = useState<string>("");
  const [cleanResult, setCleanResult] = useState<CleanReport | null>(null);
  const [dryRunModal, setDryRunModal] = useState<CleanReport | null>(null);

  const [deepCategory, setDeepCategory] = useState<string>(initial.cat);
  const [staleDays, setStaleDays] = useState<number>(30);

  // Space Lens state
  const [lensPath, setLensPath] = useState<string>("~");
  const [minColdMb, setMinColdMb] = useState<number>(100);
  const [coldDays, setColdDays] = useState<number>(90);
  const [lensReport, setLensReport] = useState<SpaceLensReport | null>(null);
  const [lensStack, setLensStack] = useState<SpaceNode[]>([]);
  const [hoveredLensPath, setHoveredLensPath] = useState<string | null>(null);

  // P1 Duplicates state
  const [dupPath, setDupPath] = useState<string>("~");
  const [dupMinKb, setDupMinKb] = useState<number>(1024);
  const [dupReport, setDupReport] = useState<DuplicateReport | null>(null);
  const [dupSelectedPaths, setDupSelectedPaths] = useState<Set<string>>(new Set());

  // P1 Uninstaller & Orphans state
  const [uninstSubTab, setUninstSubTab] = useState<UninstSubTab>("orphans");
  const [uninstReport, setUninstReport] = useState<UninstallerReport | null>(null);
  const [selectedOrphans, setSelectedOrphans] = useState<Set<string>>(new Set());

  // Audit & Settings state
  const [auditTab, setAuditTab] = useState<AuditSubTab>("history");
  const [auditHistory, setAuditHistory] = useState<AuditRecord[]>([]);
  const [rulesList, setRulesList] = useState<RuleFile[]>([]);
  const [appConfig, setAppConfig] = useState<AppConfig | null>(null);
  const [newWorkspaceInput, setNewWorkspaceInput] = useState<string>("");
  const [snapshotStatus, setSnapshotStatus] = useState<string>("");
  const [vdiskReport, setVdiskReport] = useState<VirtualDiskReport | null>(null);
  const [copiedVdiskId, setCopiedVdiskId] = useState<string | null>(null);
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const [isCleaning, setIsCleaning] = useState<boolean>(false);

  const t = (key: MessageKey) => MESSAGES[locale][key];

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
  }, [dark]);

  useEffect(() => {
    void refreshInitialData();
    if (!isTauriRuntime()) {
      const demoScan = buildDemoScanReport(null);
      setScanReport(demoScan);
      setSelectedIds(computeDefaultSelectedIds(demoScan.hits));
      setLensReport(DEMO_LENS_REPORT);
      setLensStack([DEMO_LENS_REPORT.root]);
      setDupReport(DEMO_DUPLICATES);
      setDupSelectedPaths(defaultDuplicateSelection(DEMO_DUPLICATES));
      setUninstReport(DEMO_UNINSTALLER);
      setVdiskReport(DEMO_VDISKS);
    }
  }, []);

  async function refreshInitialData() {
    try {
      const [ov, cfg, hist, rules, vdisks] = await Promise.all([
        bridgeInvoke<DiskOverview>("get_disk_overview"),
        bridgeInvoke<AppConfig>("get_app_config"),
        bridgeInvoke<AuditRecord[]>("get_audit_history", { limit: 50 }),
        bridgeInvoke<RuleFile[]>("get_builtin_rules"),
        bridgeInvoke<VirtualDiskReport>("scan_virtual_disks"),
      ]);
      setOverview(ov);
      setAppConfig(cfg);
      setAuditHistory(hist);
      setRulesList(rules);
      setVdiskReport(vdisks);
    } catch {
      // Safe fallback
    }
  }

  async function handleStartScan(categories: string[] | null = null) {
    setIsScanning(true);
    setCleanResult(null);
    setErrorBanner(null);
    setScanStatusText(t("scanning"));

    const channel = createProgressChannel((msg) => {
      if (msg.event === "RuleMatched") {
        setScanStatusText(`${msg.data.rule_id} (+${formatBytes(msg.data.added_bytes)})`);
      } else if (msg.event === "Completed") {
        setScanStatusText("");
      }
    });

    try {
      const report = await bridgeInvoke<ScanReport>("start_rule_scan", {
        categories,
        staleDays,
        onEvent: channel,
      });
      setScanReport(report);
      setSelectedIds(computeDefaultSelectedIds(report.hits));
    } catch (err) {
      if (!String(err).includes("cancelled")) {
        setErrorBanner(String(err));
      }
    } finally {
      setIsScanning(false);
    }
  }

  async function handleCancelScan() {
    await bridgeInvoke("cancel_scan");
    setIsScanning(false);
  }

  async function handleClean(dryRun: boolean) {
    if (!scanReport || isCleaning) return;
    const items: CleanItemRequest[] = scanReport.hits
      .filter((h) => selectedIds.has(h.id))
      .map((h) => ({
        rule_id: h.rule_id,
        path: h.path,
        risk: h.risk,
        delete_mode: h.delete_mode,
        native_command: h.native_command,
      }));
    if (items.length === 0) return;

    setIsCleaning(true);
    setErrorBanner(null);
    try {
      const result = await bridgeInvoke<CleanReport>("run_clean", { items, dryRun });
      if (dryRun) {
        setDryRunModal(result);
      } else {
        setDryRunModal(null);
        setCleanResult(result);
        await refreshInitialData();
        await handleStartScan(tab === "deep" && deepCategory !== "all" ? [deepCategory] : null);
      }
    } catch (err) {
      setErrorBanner(String(err));
    } finally {
      setIsCleaning(false);
    }
  }

  async function handleRunLens(target = lensPath, appendToStack = false) {
    setIsScanning(true);
    setErrorBanner(null);
    setScanStatusText(target);
    const channel = createProgressChannel((msg) => {
      if (msg.event === "DirectoryStatUpdated") {
        setScanStatusText(
          `${msg.data.scanned_files} ${t("filesCount")} · ${formatBytes(msg.data.scanned_bytes)}`
        );
      }
    });

    try {
      const report = await bridgeInvoke<SpaceLensReport>("start_space_lens", {
        path: target,
        minColdMb,
        coldDays,
        onEvent: channel,
      });
      if (appendToStack) {
        setLensStack((prev) => [...prev, report.root]);
      } else {
        setLensReport(report);
        setLensStack([report.root]);
      }
    } catch (err) {
      if (!String(err).includes("cancelled")) {
        setErrorBanner(String(err));
      }
    } finally {
      setIsScanning(false);
      setScanStatusText("");
    }
  }

  async function handleLensDrillDown(node: SpaceNode) {
    if (!node.is_dir) return;
    if (node.children.length > 0) {
      setLensStack((prev) => [...prev, node]);
    } else if (node.has_more_children) {
      // P0.3: Infinite on-demand deep drilldown past depth 4
      await handleRunLens(node.path, true);
    }
  }

  async function handleTrashColdFile(path: string) {
    if (isCleaning) return;
    setIsCleaning(true);
    setErrorBanner(null);
    try {
      await bridgeInvoke<CleanReport>("run_clean", {
        items: [
          {
            rule_id: "lens.cold_file",
            path,
            risk: "review_required",
            delete_mode: "trash",
            native_command: null,
          },
        ],
        dryRun: false,
      });
      await handleRunLens(lensPath);
      await refreshInitialData();
    } catch (err) {
      setErrorBanner(String(err));
    } finally {
      setIsCleaning(false);
    }
  }

  async function handleScanDuplicates() {
    setIsScanning(true);
    setErrorBanner(null);
    setScanStatusText(t("scanning"));
    const channel = createProgressChannel((msg) => {
      if (msg.event === "DirectoryStatUpdated") {
        setScanStatusText(msg.data.current_path);
      }
    });
    try {
      const report = await bridgeInvoke<DuplicateReport>("start_duplicate_scan", {
        paths: [dupPath],
        minSizeKb: dupMinKb,
        onEvent: channel,
      });
      setDupReport(report);
      setDupSelectedPaths(defaultDuplicateSelection(report));
    } catch (err) {
      if (!String(err).includes("cancelled")) {
        setErrorBanner(String(err));
      }
    } finally {
      setIsScanning(false);
      setScanStatusText("");
    }
  }

  async function handleCleanDuplicates() {
    if (!dupReport || isCleaning) return;
    const groups: DuplicateCleanGroup[] = dupReport.groups
      .map((g) => ({
        blake3_hash: g.blake3_hash,
        all_paths: g.entries.map((e) => e.path),
        delete_paths: g.entries.filter((e) => dupSelectedPaths.has(e.path)).map((e) => e.path),
      }))
      .filter((g) => g.delete_paths.length > 0);
    if (groups.length === 0) return;

    setIsCleaning(true);
    setErrorBanner(null);
    try {
      const res = await bridgeInvoke<CleanReport>("clean_duplicate_groups", {
        groups,
        dryRun: false,
      });
      setCleanResult(res);
      await refreshInitialData();
      await handleScanDuplicates();
    } catch (err) {
      setErrorBanner(String(err));
    } finally {
      setIsCleaning(false);
    }
  }

  async function handleScanUninstaller() {
    setIsScanning(true);
    setErrorBanner(null);
    try {
      const report = await bridgeInvoke<UninstallerReport>("scan_uninstaller", {
        minOrphanDays: 14,
      });
      setUninstReport(report);
      setSelectedOrphans(new Set());
    } catch (err) {
      if (!String(err).includes("cancelled")) {
        setErrorBanner(String(err));
      }
    } finally {
      setIsScanning(false);
    }
  }

  async function handleCleanOrphans() {
    if (selectedOrphans.size === 0 || isCleaning) return;
    setIsCleaning(true);
    setErrorBanner(null);
    try {
      const res = await bridgeInvoke<CleanReport>("clean_orphans", {
        paths: Array.from(selectedOrphans),
        dryRun: false,
      });
      setCleanResult(res);
      await refreshInitialData();
      await handleScanUninstaller();
    } catch (err) {
      setErrorBanner(String(err));
    } finally {
      setIsCleaning(false);
    }
  }

  async function handleUninstallApp(appName: string, paths: string[]) {
    if (isCleaning) return;
    setIsCleaning(true);
    setErrorBanner(null);
    try {
      const res = await bridgeInvoke<CleanReport>("uninstall_app", {
        appName,
        paths,
        dryRun: false,
      });
      setCleanResult(res);
      await refreshInitialData();
      await handleScanUninstaller();
    } catch (err) {
      setErrorBanner(String(err));
    } finally {
      setIsCleaning(false);
    }
  }

  async function handleIgnorePath(path: string, remove = false) {
    const updated = await bridgeInvoke<AppConfig>("update_ignore_list", { path, remove });
    setAppConfig(updated);
    if (!remove && scanReport) {
      setScanReport({
        ...scanReport,
        hits: scanReport.hits.filter(
          (h) => !updated.ignore_paths.some((ig) => isPathEqualOrUnder(h.path, ig))
        ),
      });
    }
  }

  async function handleWorkspaceRoot(path: string, remove = false) {
    const trimmed = path.trim();
    if (!trimmed) return;
    const updated = await bridgeInvoke<AppConfig>("update_workspace_roots", {
      path: trimmed,
      remove,
    });
    setAppConfig(updated);
    if (!remove) setNewWorkspaceInput("");
  }

  async function handleThinSnapshots() {
    if (isCleaning) return;
    setIsCleaning(true);
    setErrorBanner(null);
    try {
      const msg = await bridgeInvoke<string>("thin_local_snapshots", { gb: 20, dryRun: false });
      setSnapshotStatus(msg || "OK");
      await refreshInitialData();
    } catch (err) {
      setErrorBanner(String(err));
    } finally {
      setIsCleaning(false);
    }
  }

  async function handleCopyVdiskScript(id: string, script: string) {
    try {
      await navigator.clipboard.writeText(script);
      setCopiedVdiskId(id);
      window.setTimeout(() => {
        setCopiedVdiskId((cur) => (cur === id ? null : cur));
      }, 2000);
    } catch {
      // Clipboard API unavailable in headless context
    }
  }

  const filteredHits = useMemo(() => {
    if (!scanReport) return [];
    if (tab === "deep" && deepCategory !== "all") {
      return scanReport.hits.filter((h) => h.category === deepCategory);
    }
    return scanReport.hits;
  }, [scanReport, tab, deepCategory]);

  const selectedStats = useMemo(() => {
    let total = 0;
    let perm = 0;
    let trash = 0;
    for (const h of filteredHits) {
      if (!selectedIds.has(h.id)) continue;
      total += h.allocated_bytes;
      if (h.risk === "review_required" || h.delete_mode === "trash") {
        trash += h.allocated_bytes;
      } else {
        perm += h.allocated_bytes;
      }
    }
    return { total, perm, trash };
  }, [filteredHits, selectedIds]);

  const currentLensNode = lensStack[lensStack.length - 1] ?? null;

  const toggleHit = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleRiskGroup = (risk: RiskLevel, checked: boolean) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      for (const h of filteredHits) {
        if (h.risk === risk) {
          if (checked) next.add(h.id);
          else next.delete(h.id);
        }
      }
      return next;
    });
  };

  return (
    <div className="flex h-screen overflow-hidden bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100">
      {/* Sidebar */}
      <aside className="flex w-64 shrink-0 flex-col justify-between border-r border-slate-200 bg-white/90 p-4 dark:border-slate-800 dark:bg-slate-900/80">
        <div>
          <div className="flex items-center gap-2.5 px-2 py-1">
            <svg
              viewBox="0 0 128 128"
              fill="none"
              aria-label="ClearLens Logo"
              className="h-9 w-9 shrink-0 rounded-[9px] shadow-sm ring-1 ring-slate-200/80 dark:ring-slate-700/60"
            >
              <defs>
                <linearGradient id="cl-sidebar-grad" x1="16" y1="16" x2="112" y2="112" gradientUnits="userSpaceOnUse">
                  <stop offset="0%" stopColor="#0EA5E9" />
                  <stop offset="55%" stopColor="#14B8A6" />
                  <stop offset="100%" stopColor="#6366F1" />
                </linearGradient>
                <linearGradient id="cl-sidebar-inner" x1="36" y1="36" x2="92" y2="92" gradientUnits="userSpaceOnUse">
                  <stop offset="0%" stopColor="#38BDF8" stopOpacity="0.28" />
                  <stop offset="100%" stopColor="#2DD4BF" stopOpacity="0.12" />
                </linearGradient>
              </defs>
              <rect width="128" height="128" rx="30" fill="#0F172A" />
              <circle cx="64" cy="64" r="42" stroke="url(#cl-sidebar-grad)" strokeWidth="10" />
              <circle cx="64" cy="64" r="28" fill="url(#cl-sidebar-inner)" />
              <path
                d="M64 40L68.8 55.2L84 60L68.8 64.8L64 80L59.2 64.8L44 60L59.2 55.2L64 40Z"
                fill="url(#cl-sidebar-grad)"
              />
              <circle cx="94" cy="94" r="7" fill="#14B8A6" />
            </svg>
            <div>
              <div className="text-base font-bold tracking-tight">ClearLens</div>
              <div className="text-[11px] text-slate-500 dark:text-slate-400">v0.1.1 · clens</div>
            </div>
          </div>

          {overview && (
            <div className="mt-4 rounded-xl border border-slate-200/80 bg-slate-50 p-3 dark:border-slate-800 dark:bg-slate-950/60">
              <div className="flex items-center justify-between text-xs font-medium">
                <span className="flex items-center gap-1.5 text-slate-600 dark:text-slate-300">
                  <HardDrive className="h-3.5 w-3.5 text-sky-500" />
                  {overview.mount_point}
                </span>
                <span className="text-slate-500">{formatBytes(overview.total_bytes)}</span>
              </div>
              <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-sky-500 to-teal-400"
                  style={{
                    width: `${
                      overview.total_bytes > 0
                        ? Math.min(100, (overview.used_bytes / overview.total_bytes) * 100)
                        : 0
                    }%`,
                  }}
                />
              </div>
              <div className="mt-2 flex justify-between text-[11px] text-slate-500 dark:text-slate-400">
                <span>
                  {t("diskFree")}:{" "}
                  <strong className="text-slate-800 dark:text-slate-200">
                    {formatBytes(overview.available_bytes)}
                  </strong>
                </span>
              </div>
              {overview.purgeable_bytes > 0 && (
                <div className="mt-1 text-[11px] text-amber-600 dark:text-amber-400">
                  {t("apfsPurgeable")}: {formatBytes(overview.purgeable_bytes)}
                </div>
              )}
            </div>
          )}

          <nav className="mt-4 space-y-1">
            {(
              [
                ["smart", t("navSmart"), ShieldCheck],
                ["deep", t("navDeep"), Layers],
                ["lens", t("navLens"), FileSearch],
                ["duplicates", t("navDuplicates"), Copy],
                ["uninstaller", t("navUninstaller"), PackageX],
                ["audit", t("navAudit"), History],
              ] as const
            ).map(([id, label, Icon]) => (
              <button
                key={id}
                onClick={() => setTab(id)}
                className={`flex w-full items-center gap-2.5 rounded-xl px-3 py-2 text-sm font-medium transition ${
                  tab === id
                    ? "bg-sky-500/10 text-sky-600 dark:bg-sky-500/15 dark:text-sky-400"
                    : "text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800/70"
                }`}
              >
                <Icon className="h-4 w-4" />
                {label}
              </button>
            ))}
          </nav>
        </div>

        {/* Footer Controls */}
        <div className="space-y-2 border-t border-slate-200 pt-3 dark:border-slate-800">
          <div className="flex items-center justify-between rounded-xl bg-slate-100 p-1 text-xs dark:bg-slate-800">
            <button
              onClick={() => setProMode(false)}
              className={`flex-1 rounded-lg py-1.5 font-medium transition ${
                !proMode ? "bg-white shadow-sm dark:bg-slate-700" : "text-slate-500"
              }`}
            >
              {t("modeSmart")}
            </button>
            <button
              onClick={() => setProMode(true)}
              className={`flex-1 rounded-lg py-1.5 font-medium transition ${
                proMode ? "bg-white shadow-sm dark:bg-slate-700" : "text-slate-500"
              }`}
            >
              {t("modePro")}
            </button>
          </div>

          <div className="flex gap-2">
            <button
              onClick={() => setLocale(locale === "zh-CN" ? "en" : "zh-CN")}
              className="flex flex-1 items-center justify-center gap-1.5 rounded-lg border border-slate-200 py-1.5 text-xs font-medium hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800"
            >
              <Languages className="h-3.5 w-3.5" />
              {locale === "zh-CN" ? "EN" : "中文"}
            </button>
            <button
              onClick={() => setDark(!dark)}
              className="flex flex-1 items-center justify-center gap-1.5 rounded-lg border border-slate-200 py-1.5 text-xs font-medium hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800"
            >
              {dark ? <Sun className="h-3.5 w-3.5" /> : <Moon className="h-3.5 w-3.5" />}
              {dark ? "Light" : "Dark"}
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex flex-1 flex-col overflow-y-auto p-6">
        {overview && !overview.fda_granted && (
          <div className="mb-4 flex items-center justify-between rounded-xl border border-amber-300/60 bg-amber-50 px-4 py-3 text-sm dark:border-amber-500/30 dark:bg-amber-500/10">
            <div className="flex items-center gap-3">
              <TriangleAlert className="h-5 w-5 shrink-0 text-amber-500" />
              <div>
                <div className="font-semibold text-amber-900 dark:text-amber-200">
                  {t("fdaTitle")}
                </div>
                <div className="text-xs text-amber-800/80 dark:text-amber-300/80">
                  {t("fdaDesc")}
                </div>
              </div>
            </div>
            <button
              onClick={() => bridgeInvoke("open_fda_settings")}
              className="shrink-0 rounded-lg bg-amber-500 px-3 py-1.5 text-xs font-semibold text-white hover:bg-amber-600"
            >
              {t("fdaButton")}
            </button>
          </div>
        )}

        {errorBanner && (
          <div className="mb-4 flex items-center justify-between rounded-xl border border-rose-300 bg-rose-50 px-4 py-3 text-sm text-rose-900 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-200">
            <div className="flex items-center gap-2 font-medium">
              <TriangleAlert className="h-4 w-4 shrink-0 text-rose-500" />
              <span className="break-all">{errorBanner}</span>
            </div>
            <button onClick={() => setErrorBanner(null)} className="opacity-70 hover:opacity-100">
              <X className="h-4 w-4" />
            </button>
          </div>
        )}

        {cleanResult && (
          <div
            className={`mb-4 flex items-center justify-between rounded-xl border px-4 py-3 text-sm ${
              cleanResult.dry_run
                ? "border-sky-300 bg-sky-50 text-sky-900 dark:border-sky-500/30 dark:bg-sky-500/10 dark:text-sky-200"
                : "border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-500/30 dark:bg-emerald-500/10 dark:text-emerald-200"
            }`}
          >
            <div className="flex items-center gap-2 font-medium">
              <CircleCheck className="h-4 w-4" />
              {cleanResult.dry_run ? t("dryRunBanner") : t("cleanDoneBanner")}:{" "}
              <strong>{formatBytes(cleanResult.total_freed_bytes)}</strong> (
              {cleanResult.succeeded_count} items)
            </div>
            <button onClick={() => setCleanResult(null)} className="opacity-70 hover:opacity-100">
              <X className="h-4 w-4" />
            </button>
          </div>
        )}

        {(tab === "smart" || tab === "deep") && (
          <div className="flex flex-1 flex-col gap-5">
            <div className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-slate-200 bg-white p-5 shadow-xs dark:border-slate-800 dark:bg-slate-900">
              <div>
                <h1 className="text-xl font-bold">
                  {tab === "smart" ? t("navSmart") : t("deepTitle")}
                </h1>
                <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                  {scanStatusText || t("skipSymlinkNotice")}
                </p>
              </div>

              <div className="flex items-center gap-3">
                {tab === "deep" && (
                  <label className="flex items-center gap-2 rounded-xl border border-slate-200 px-3 py-2 text-xs dark:border-slate-700">
                    <span className="text-slate-500">{t("staleDaysLabel")}:</span>
                    <select
                      value={staleDays}
                      onChange={(e) => setStaleDays(Number(e.target.value))}
                      className="bg-transparent font-semibold outline-none"
                    >
                      {[14, 30, 60, 90].map((d) => (
                        <option key={d} value={d} className="dark:bg-slate-900">
                          {d} {t("daysUnit")}
                        </option>
                      ))}
                    </select>
                  </label>
                )}

                {isScanning ? (
                  <button
                    onClick={handleCancelScan}
                    className="flex items-center gap-2 rounded-xl bg-rose-500 px-4 py-2.5 text-sm font-semibold text-white hover:bg-rose-600"
                  >
                    <CircleX className="h-4 w-4" />
                    {t("cancel")}
                  </button>
                ) : (
                  <button
                    onClick={() =>
                      handleStartScan(
                        tab === "deep" && deepCategory !== "all" ? [deepCategory] : null
                      )
                    }
                    className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-sky-500 to-teal-500 px-5 py-2.5 text-sm font-semibold text-white shadow-sm hover:opacity-95"
                  >
                    <RefreshCw className="h-4 w-4" />
                    {scanReport ? t("rescan") : t("scanStart")}
                  </button>
                )}
              </div>
            </div>

            {tab === "deep" && (
              <div className="flex flex-wrap gap-2">
                {(
                  [
                    ["all", t("catAll")],
                    ["dev_ai", t("catDevAi")],
                    ["social_office", t("catSocial")],
                    ["creative_media", t("catCreative")],
                    ["gaming", t("catGaming")],
                    ["system", t("catSystem")],
                    ["browsers", t("catBrowsers")],
                  ] as const
                ).map(([cat, label]) => (
                  <button
                    key={cat}
                    onClick={() => setDeepCategory(cat)}
                    className={`rounded-xl px-3.5 py-2 text-xs font-semibold transition ${
                      deepCategory === cat
                        ? "bg-sky-500 text-white"
                        : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-100 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300"
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>
            )}

            {!scanReport ? (
              <div className="flex flex-1 flex-col items-center justify-center rounded-2xl border border-dashed border-slate-300 bg-white/60 p-12 text-center dark:border-slate-800 dark:bg-slate-900/40">
                <ShieldCheck className="h-12 w-12 text-sky-500/80" />
                <h2 className="mt-4 text-lg font-semibold">{t("emptyStateTitle")}</h2>
                <p className="mt-1.5 max-w-md text-sm text-slate-500 dark:text-slate-400">
                  {t("emptyStateDesc")}
                </p>
              </div>
            ) : (
              <>
                <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                  {(
                    [
                      ["safe", t("riskSafe"), t("riskSafeDesc"), scanReport.risk_summary.safe_bytes, "emerald"],
                      [
                        "recreatable",
                        t("riskRecreatable"),
                        t("riskRecreatableDesc"),
                        scanReport.risk_summary.recreatable_bytes,
                        "amber",
                      ],
                      [
                        "review_required",
                        t("riskReview"),
                        t("riskReviewDesc"),
                        scanReport.risk_summary.review_required_bytes,
                        "rose",
                      ],
                    ] as const
                  ).map(([risk, title, desc, bytes, tone]) => {
                    const groupHits = filteredHits.filter((h) => h.risk === risk);
                    const allChecked =
                      groupHits.length > 0 && groupHits.every((h) => selectedIds.has(h.id));
                    return (
                      <div
                        key={risk}
                        className="rounded-2xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900"
                      >
                        <div className="flex items-start justify-between">
                          <div>
                            <span
                              className={`inline-block rounded-full px-2.5 py-0.5 text-[11px] font-bold ${
                                tone === "emerald"
                                  ? "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400"
                                  : tone === "amber"
                                    ? "bg-amber-500/15 text-amber-600 dark:text-amber-400"
                                    : "bg-rose-500/15 text-rose-600 dark:text-rose-400"
                              }`}
                            >
                              {title}
                            </span>
                            <div className="mt-2 text-2xl font-bold">{formatBytes(bytes)}</div>
                          </div>
                          <input
                            type="checkbox"
                            checked={allChecked}
                            disabled={groupHits.length === 0}
                            onChange={(e) => toggleRiskGroup(risk, e.target.checked)}
                            className="h-4 w-4 rounded accent-sky-500"
                          />
                        </div>
                        <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">{desc}</p>
                      </div>
                    );
                  })}
                </div>

                <div className="flex-1 overflow-hidden rounded-2xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
                  <div className="max-h-[380px] overflow-y-auto divide-y divide-slate-100 dark:divide-slate-800">
                    {filteredHits.map((hit: ScanHit) => (
                      <div
                        key={hit.id}
                        className="flex items-center justify-between gap-4 px-4 py-3 hover:bg-slate-50 dark:hover:bg-slate-800/40"
                      >
                        <div className="flex min-w-0 items-start gap-3">
                          <input
                            type="checkbox"
                            checked={selectedIds.has(hit.id)}
                            onChange={() => toggleHit(hit.id)}
                            className="mt-1 h-4 w-4 shrink-0 rounded accent-sky-500"
                          />
                          <div className="min-w-0">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="font-semibold text-sm">
                                {locale === "zh-CN" ? hit.title_zh : hit.title}
                              </span>
                              {proMode && (
                                <code className="rounded bg-slate-100 px-1.5 py-0.5 text-[11px] text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                                  {hit.rule_id}
                                </code>
                              )}
                              {hit.locked_by_process && (
                                <span className="rounded bg-amber-500/15 px-1.5 py-0.5 text-[11px] font-medium text-amber-600 dark:text-amber-400">
                                  {t("lockedWarning")}: {hit.locked_by_process}
                                </span>
                              )}
                            </div>
                            {proMode && (
                              <>
                                <div className="mt-0.5 truncate font-mono text-[11px] text-slate-500">
                                  {hit.path}
                                </div>
                                <div className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                                  {locale === "zh-CN" ? hit.impact_note_zh : hit.impact_note}
                                </div>
                              </>
                            )}
                          </div>
                        </div>

                        <div className="flex shrink-0 items-center gap-3">
                          <div className="text-right">
                            <div className="text-sm font-bold">{formatBytes(hit.allocated_bytes)}</div>
                            <div className="text-[11px] text-slate-500">
                              {hit.file_count.toLocaleString()} {t("filesCount")}
                            </div>
                          </div>
                          {proMode && (
                            <div className="flex gap-1">
                              <button
                                title={t("reveal")}
                                onClick={() => bridgeInvoke("reveal_in_folder", { path: hit.path })}
                                className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-200 dark:hover:bg-slate-700"
                              >
                                <FolderOpen className="h-4 w-4" />
                              </button>
                              <button
                                title={t("ignore")}
                                onClick={() => handleIgnorePath(hit.path)}
                                className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-200 dark:hover:bg-slate-700"
                              >
                                <Eye className="h-4 w-4" />
                              </button>
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-slate-200 bg-white px-5 py-3.5 dark:border-slate-800 dark:bg-slate-900">
                  <div className="text-sm">
                    {t("selectedSummary")}: <strong>{formatBytes(selectedStats.total)}</strong>
                    <span className="ml-3 text-xs text-slate-500">
                      ({t("permanentNote")}: {formatBytes(selectedStats.perm)} · {t("trashNote")}:{" "}
                      {formatBytes(selectedStats.trash)})
                    </span>
                  </div>
                  <div className="flex gap-2.5">
                    <button
                      disabled={selectedStats.total === 0 || isCleaning}
                      onClick={() => handleClean(true)}
                      className="rounded-xl border border-slate-300 px-4 py-2 text-sm font-semibold hover:bg-slate-100 disabled:opacity-40 dark:border-slate-700 dark:hover:bg-slate-800"
                    >
                      {t("dryRunBtn")}
                    </button>
                    <button
                      disabled={selectedStats.total === 0 || isCleaning}
                      onClick={() => handleClean(false)}
                      className="flex items-center gap-2 rounded-xl bg-sky-500 px-5 py-2 text-sm font-semibold text-white hover:bg-sky-600 disabled:opacity-40"
                    >
                      <Trash2 className="h-4 w-4" />
                      {t("cleanSelectedBtn")}
                    </button>
                  </div>
                </div>
              </>
            )}
          </div>
        )}

        {tab === "lens" && (
          <div className="flex flex-1 flex-col gap-4">
            <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
              <div className="flex flex-1 flex-wrap items-center gap-2">
                <input
                  value={lensPath}
                  onChange={(e) => setLensPath(e.target.value)}
                  placeholder={t("lensPlaceholder")}
                  className="w-full max-w-md rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm outline-none focus:border-sky-500 dark:border-slate-700 dark:bg-slate-950"
                />
                <button
                  onClick={() => handleRunLens(lensPath)}
                  className="rounded-xl bg-sky-500 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-600"
                >
                  {t("lensScanBtn")}
                </button>
                {overview?.volumes?.map((v) => (
                  <button
                    key={v.mount_point}
                    onClick={() => {
                      setLensPath(v.mount_point);
                      void handleRunLens(v.mount_point);
                    }}
                    className="rounded-lg border border-slate-200 px-2.5 py-1 text-xs font-medium hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800"
                  >
                    {v.label}
                  </button>
                ))}
              </div>
              <div className="flex items-center gap-2 text-xs">
                <span className="text-slate-500">{t("minSizeLabel")}:</span>
                <select
                  value={minColdMb}
                  onChange={(e) => setMinColdMb(Number(e.target.value))}
                  className="rounded-lg border border-slate-200 bg-transparent px-2 py-1 dark:border-slate-700"
                >
                  {[100, 500, 1024].map((mb) => (
                    <option key={mb} value={mb} className="dark:bg-slate-900">
                      {mb} MB
                    </option>
                  ))}
                </select>
                <span className="text-slate-500">{t("inactiveLabel")}:</span>
                <select
                  value={coldDays}
                  onChange={(e) => setColdDays(Number(e.target.value))}
                  className="rounded-lg border border-slate-200 bg-transparent px-2 py-1 dark:border-slate-700"
                >
                  {[30, 90, 180].map((d) => (
                    <option key={d} value={d} className="dark:bg-slate-900">
                      {d} d
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {currentLensNode && (
              <>
                <div className="flex flex-wrap items-center gap-1 text-xs text-slate-500">
                  {lensStack.map((n, idx) => (
                    <React.Fragment key={`${n.path}-${idx}`}>
                      {idx > 0 && <ChevronRight className="h-3.5 w-3.5" />}
                      <button
                        onClick={() => setLensStack(lensStack.slice(0, idx + 1))}
                        className="rounded px-1.5 py-0.5 font-medium hover:bg-slate-200 dark:hover:bg-slate-800"
                      >
                        {n.name}
                      </button>
                    </React.Fragment>
                  ))}
                </div>

                <div className="grid flex-1 grid-cols-1 gap-4 lg:grid-cols-12">
                  <div className="overflow-y-auto rounded-2xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900 lg:col-span-5">
                    <div className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
                      {t("lensTreeHeader")}
                    </div>
                    <div className="space-y-2">
                      {currentLensNode.children.map((ch) => {
                        const pct =
                          currentLensNode.allocated_bytes > 0
                            ? (ch.allocated_bytes / currentLensNode.allocated_bytes) * 100
                            : 0;
                        return (
                          <div
                            key={`${ch.path}-${ch.name}`}
                            onMouseEnter={() => setHoveredLensPath(ch.path)}
                            onMouseLeave={() => setHoveredLensPath(null)}
                            onClick={() => void handleLensDrillDown(ch)}
                            className={`cursor-pointer rounded-xl p-2 transition ${
                              hoveredLensPath === ch.path
                                ? "bg-sky-500/10"
                                : "hover:bg-slate-50 dark:hover:bg-slate-800/60"
                            }`}
                          >
                            <div className="flex justify-between text-xs font-medium">
                              <span className="truncate">
                                {ch.name}
                                {ch.has_more_children ? " ›" : ""}
                              </span>
                              <span className="shrink-0 font-semibold">
                                {formatBytes(ch.allocated_bytes)} ({pct.toFixed(1)}%)
                              </span>
                            </div>
                            <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800">
                              <div
                                className="h-full rounded-full bg-sky-500"
                                style={{ width: `${Math.min(100, pct)}%` }}
                              />
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  <div className="flex flex-col rounded-2xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900 lg:col-span-7">
                    <div className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
                      {t("lensTreemapHeader")}
                    </div>
                    <div className="flex-1">
                      <TreemapCanvas
                        node={currentLensNode}
                        hoveredPath={hoveredLensPath}
                        onHoverPath={setHoveredLensPath}
                        onDrillDown={(n) => void handleLensDrillDown(n)}
                      />
                    </div>
                  </div>
                </div>

                {lensReport && lensReport.cold_files.length > 0 && (
                  <div className="rounded-2xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
                    <div className="mb-3 text-sm font-bold">{t("coldRadarTitle")}</div>
                    <div className="max-h-48 overflow-y-auto divide-y divide-slate-100 dark:divide-slate-800">
                      {lensReport.cold_files.map((cf) => (
                        <div key={cf.path} className="flex items-center justify-between py-2 text-xs">
                          <div className="min-w-0 pr-4">
                            <div className="truncate font-semibold">{cf.name}</div>
                            <div className="truncate font-mono text-[11px] text-slate-500">
                              {cf.path}
                            </div>
                          </div>
                          <div className="flex shrink-0 items-center gap-3">
                            <span className="text-slate-500">{cf.inactive_days}d</span>
                            <span className="font-bold">{formatBytes(cf.allocated_bytes)}</span>
                            <button
                              disabled={isCleaning}
                              onClick={() => handleTrashColdFile(cf.path)}
                              className="rounded-lg bg-rose-500/10 px-2.5 py-1 font-semibold text-rose-600 hover:bg-rose-500/20 disabled:opacity-40 dark:text-rose-400"
                            >
                              {t("moveToTrash")}
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {/* P1.1: BLAKE3 Duplicate Finder Tab */}
        {tab === "duplicates" && (
          <div className="flex flex-1 flex-col gap-4">
            <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
              <div>
                <h1 className="text-xl font-bold">{t("dupTitle")}</h1>
                <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{t("dupDesc")}</p>
              </div>
              <div className="flex items-center gap-2">
                <input
                  value={dupPath}
                  onChange={(e) => setDupPath(e.target.value)}
                  className="w-48 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-xs dark:border-slate-700 dark:bg-slate-950"
                />
                <select
                  value={dupMinKb}
                  onChange={(e) => setDupMinKb(Number(e.target.value))}
                  className="rounded-xl border border-slate-200 bg-transparent px-2.5 py-2 text-xs dark:border-slate-700"
                >
                  <option value={100} className="dark:bg-slate-900">≥ 100 KB</option>
                  <option value={1024} className="dark:bg-slate-900">≥ 1 MB</option>
                  <option value={10240} className="dark:bg-slate-900">≥ 10 MB</option>
                </select>
                <button
                  onClick={() => void handleScanDuplicates()}
                  className="rounded-xl bg-sky-500 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-600"
                >
                  {t("dupScanBtn")}
                </button>
              </div>
            </div>

            {dupReport && (
              <>
                <div className="flex flex-wrap items-center justify-between rounded-2xl border border-slate-200 bg-white px-5 py-3 text-xs dark:border-slate-800 dark:bg-slate-900">
                  <div className="flex gap-4">
                    <span>
                      <strong>{dupReport.groups.length}</strong> {t("dupGroupsCount")}
                    </span>
                    <span>
                      {t("dupWasted")}: <strong>{formatBytes(dupReport.total_wasted_bytes)}</strong>
                    </span>
                    <span className="text-slate-500">
                      {t("dupHardlinksSkipped")}: {dupReport.skipped_hardlinks}
                    </span>
                  </div>
                  <button
                    disabled={dupSelectedPaths.size === 0 || isCleaning}
                    onClick={() => void handleCleanDuplicates()}
                    className="rounded-xl bg-rose-500 px-4 py-1.5 text-xs font-semibold text-white hover:bg-rose-600 disabled:opacity-40"
                  >
                    {t("dupCleanBtn")} ({dupSelectedPaths.size})
                  </button>
                </div>

                <div className="flex-1 space-y-3 overflow-y-auto">
                  {dupReport.groups.map((grp) => {
                    const groupPaths = grp.entries.map((e) => e.path);
                    const selectedInGroup = groupPaths.filter((p) => dupSelectedPaths.has(p)).length;
                    return (
                      <div
                        key={grp.blake3_hash}
                        className="rounded-2xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900"
                      >
                        <div className="mb-2 flex items-center justify-between text-xs">
                          <code className="rounded bg-slate-100 px-2 py-0.5 font-mono text-sky-600 dark:bg-slate-800 dark:text-sky-400">
                            BLAKE3: {grp.blake3_hash.slice(0, 16)}…
                          </code>
                          <span className="font-semibold text-amber-600 dark:text-amber-400">
                            {formatBytes(grp.file_size)} × {grp.entries.length} · {t("dupWasted")}{" "}
                            {formatBytes(grp.wasted_bytes)}
                          </span>
                        </div>
                        <div className="divide-y divide-slate-100 dark:divide-slate-800">
                          {grp.entries.map((entry) => {
                            const checked = dupSelectedPaths.has(entry.path);
                            const isLastSurvivor =
                              !checked && selectedInGroup + 1 >= groupPaths.length;
                            return (
                              <div
                                key={entry.path}
                                className="flex items-center justify-between py-2 text-xs"
                              >
                                <div className="flex min-w-0 items-center gap-3">
                                  <input
                                    type="checkbox"
                                    checked={checked}
                                    disabled={isLastSurvivor}
                                    onChange={() =>
                                      setDupSelectedPaths((prev) =>
                                        toggleDuplicateDeletion(prev, groupPaths, entry.path)
                                      )
                                    }
                                    className="h-4 w-4 accent-rose-500 disabled:opacity-30"
                                  />
                                  <div className="min-w-0">
                                    <div className="flex items-center gap-2">
                                      <span className="font-semibold">{entry.name}</span>
                                      {entry.recommended_keep && (
                                        <span className="rounded-full bg-emerald-500/15 px-2 py-0.5 text-[10px] font-bold text-emerald-600 dark:text-emerald-400">
                                          {t("dupKeepBadge")}
                                        </span>
                                      )}
                                    </div>
                                    <div className="truncate font-mono text-[11px] text-slate-500">
                                      {entry.path}
                                    </div>
                                  </div>
                                </div>
                                <span className="shrink-0 font-semibold">
                                  {formatBytes(entry.allocated_bytes)}
                                </span>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </>
            )}
          </div>
        )}

        {/* P1.2: App Uninstaller & Orphan Residue Hunter Tab */}
        {tab === "uninstaller" && (
          <div className="flex flex-1 flex-col gap-4">
            <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
              <div>
                <h1 className="text-xl font-bold">{t("uninstTitle")}</h1>
                <div className="mt-2 flex gap-2">
                  {(
                    [
                      ["orphans", t("uninstSubOrphans")],
                      ["apps", t("uninstSubApps")],
                    ] as const
                  ).map(([sub, label]) => (
                    <button
                      key={sub}
                      onClick={() => setUninstSubTab(sub)}
                      className={`rounded-lg px-3 py-1.5 text-xs font-semibold ${
                        uninstSubTab === sub
                          ? "bg-sky-500 text-white"
                          : "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300"
                      }`}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>
              <button
                onClick={() => void handleScanUninstaller()}
                className="rounded-xl bg-sky-500 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-600"
              >
                {t("uninstScanBtn")}
              </button>
            </div>

            {uninstReport && uninstSubTab === "orphans" && (
              <div className="flex flex-1 flex-col gap-3">
                <div className="flex items-center justify-between rounded-xl border border-slate-200 bg-white px-4 py-3 text-xs dark:border-slate-800 dark:bg-slate-900">
                  <span>
                    Total: <strong>{formatBytes(uninstReport.total_orphan_bytes)}</strong> (
                    {uninstReport.orphans.length})
                  </span>
                  <button
                    disabled={selectedOrphans.size === 0 || isCleaning}
                    onClick={() => void handleCleanOrphans()}
                    className="rounded-lg bg-rose-500 px-3.5 py-1.5 font-semibold text-white hover:bg-rose-600 disabled:opacity-40"
                  >
                    {t("uninstCleanOrphansBtn")} ({selectedOrphans.size})
                  </button>
                </div>
                <div className="flex-1 overflow-y-auto rounded-2xl border border-slate-200 bg-white p-4 divide-y divide-slate-100 dark:border-slate-800 dark:bg-slate-900 dark:divide-slate-800">
                  {uninstReport.orphans.map((o) => (
                    <div key={o.path} className="flex items-center justify-between py-3 text-xs">
                      <div className="flex min-w-0 items-center gap-3">
                        <input
                          type="checkbox"
                          checked={selectedOrphans.has(o.path)}
                          onChange={() =>
                            setSelectedOrphans((prev) => {
                              const next = new Set(prev);
                              if (next.has(o.path)) next.delete(o.path);
                              else next.add(o.path);
                              return next;
                            })
                          }
                          className="h-4 w-4 accent-rose-500"
                        />
                        <div className="min-w-0">
                          <div className="font-semibold">
                            {o.name}{" "}
                            <span className="ml-1 rounded bg-slate-100 px-1.5 py-0.5 text-[10px] dark:bg-slate-800">
                              {o.location_kind}
                            </span>
                          </div>
                          <div className="truncate font-mono text-[11px] text-slate-500">
                            {o.path}
                          </div>
                        </div>
                      </div>
                      <div className="shrink-0 text-right">
                        <div className="font-bold">{formatBytes(o.allocated_bytes)}</div>
                        <div className="text-[11px] text-slate-500">{o.inactive_days}d</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {uninstReport && uninstSubTab === "apps" && (
              <div className="flex-1 space-y-3 overflow-y-auto">
                {uninstReport.apps.map((app) => (
                  <div
                    key={app.install_path}
                    className="rounded-2xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900"
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="text-sm font-bold">{app.name}</div>
                        <div className="font-mono text-[11px] text-slate-500">
                          {app.bundle_id || app.install_path}
                        </div>
                      </div>
                      <div className="flex items-center gap-4 text-xs">
                        <span>
                          {t("uninstAppSize")}: <strong>{formatBytes(app.app_bytes)}</strong>
                        </span>
                        <span>
                          {t("uninstResidueSize")}:{" "}
                          <strong className="text-amber-500">{formatBytes(app.residue_bytes)}</strong>
                        </span>
                        <button
                          disabled={isCleaning}
                          onClick={() =>
                            void handleUninstallApp(app.name, [
                              app.install_path,
                              ...app.residues.map((r) => r.path),
                            ])
                          }
                          className="rounded-lg bg-rose-500/10 px-3 py-1.5 font-semibold text-rose-600 hover:bg-rose-500/20 disabled:opacity-40 dark:text-rose-400"
                        >
                          {t("uninstRemoveAppBtn")}
                        </button>
                      </div>
                    </div>
                    {app.residues.length > 0 && (
                      <div className="mt-2 space-y-1 border-t border-slate-100 pt-2 text-[11px] text-slate-500 dark:border-slate-800">
                        {app.residues.map((r) => (
                          <div key={r.path} className="flex justify-between">
                            <span className="truncate font-mono">
                              [{r.kind}] {r.path}
                            </span>
                            <span className="shrink-0 font-semibold">
                              {formatBytes(r.allocated_bytes)}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Audit & Settings Tab */}
        {tab === "audit" && (
          <div className="flex flex-1 flex-col gap-4">
            <div className="flex flex-wrap gap-2">
              {(
                [
                  ["history", t("auditTabHistory")],
                  ["settings", t("auditTabSettings")],
                  ["ignore", t("auditTabIgnore")],
                  ["rules", t("auditTabRules")],
                ] as const
              ).map(([k, label]) => (
                <button
                  key={k}
                  onClick={() => setAuditTab(k)}
                  className={`rounded-xl px-4 py-2 text-sm font-semibold ${
                    auditTab === k
                      ? "bg-sky-500 text-white"
                      : "border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>

            <div className="flex-1 overflow-y-auto rounded-2xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
              {auditTab === "history" && (
                <div className="space-y-2 text-xs">
                  {auditHistory.length === 0 ? (
                    <div className="py-8 text-center text-slate-500">{t("noAudit")}</div>
                  ) : (
                    auditHistory.map((rec, i) => (
                      <div
                        key={i}
                        className="flex items-center justify-between border-b border-slate-100 py-2 dark:border-slate-800"
                      >
                        <div className="min-w-0">
                          <div className="font-semibold">{rec.rule_id}</div>
                          <div className="truncate font-mono text-[11px] text-slate-500">
                            {rec.path}
                          </div>
                        </div>
                        <div className="shrink-0 text-right">
                          <div className="font-bold">{formatBytes(rec.bytes_freed)}</div>
                          <div className="text-[11px] text-slate-500">{rec.method}</div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              )}

              {auditTab === "settings" && (
                <div className="space-y-6">
                  <div>
                    <h3 className="text-sm font-bold">{t("workspaceRootsTitle")}</h3>
                    <div className="mt-2 flex gap-2">
                      <input
                        value={newWorkspaceInput}
                        onChange={(e) => setNewWorkspaceInput(e.target.value)}
                        placeholder={t("workspaceAddPlaceholder")}
                        className="flex-1 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-xs dark:border-slate-700 dark:bg-slate-950"
                      />
                      <button
                        onClick={() => void handleWorkspaceRoot(newWorkspaceInput, false)}
                        className="flex items-center gap-1 rounded-xl bg-sky-500 px-3.5 py-2 text-xs font-semibold text-white hover:bg-sky-600"
                      >
                        <Plus className="h-3.5 w-3.5" />
                        {t("addBtn")}
                      </button>
                    </div>
                    <div className="mt-3 space-y-1.5 text-xs">
                      {!appConfig || appConfig.workspace_roots.length === 0 ? (
                        <div className="text-slate-500">{t("noWorkspaces")}</div>
                      ) : (
                        appConfig.workspace_roots.map((ws) => (
                          <div
                            key={ws}
                            className="flex items-center justify-between rounded-lg border border-slate-200 px-3 py-2 dark:border-slate-800"
                          >
                            <span className="font-mono">{ws}</span>
                            <button
                              onClick={() => void handleWorkspaceRoot(ws, true)}
                              className="rounded bg-rose-500/10 px-2 py-0.5 font-semibold text-rose-600"
                            >
                              {t("removeIgnore")}
                            </button>
                          </div>
                        ))
                      )}
                    </div>
                  </div>

                  {overview && overview.local_snapshots_count > 0 && (
                    <div className="rounded-xl border border-amber-300/60 bg-amber-50/70 p-4 dark:border-amber-500/30 dark:bg-amber-500/10">
                      <div className="flex items-center justify-between gap-4">
                        <div>
                          <div className="text-sm font-bold">
                            {t("snapshotsTitle")} ({overview.local_snapshots_count})
                          </div>
                          <div className="mt-1 text-xs text-slate-600 dark:text-slate-300">
                            {t("snapshotsDesc")}
                          </div>
                          {snapshotStatus && (
                            <div className="mt-1 font-mono text-[11px] text-amber-600 dark:text-amber-300">
                              {snapshotStatus}
                            </div>
                          )}
                        </div>
                        <button
                          disabled={isCleaning}
                          onClick={() => void handleThinSnapshots()}
                          className="shrink-0 rounded-xl bg-amber-500 px-3.5 py-2 text-xs font-semibold text-white hover:bg-amber-600 disabled:opacity-40"
                        >
                          {t("snapshotsThinBtn")}
                        </button>
                      </div>
                    </div>
                  )}

                  {/* WSL2 / Docker Virtual Disk Compaction Guide */}
                  <div className="rounded-xl border border-slate-200 p-4 dark:border-slate-800">
                    <div className="flex items-center justify-between gap-2">
                      <div>
                        <h3 className="text-sm font-bold">{t("vdiskTitle")}</h3>
                        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                          {t("vdiskDesc")}
                        </p>
                      </div>
                      <button
                        onClick={() => void refreshInitialData()}
                        className="shrink-0 rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs font-medium hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800"
                      >
                        <RefreshCw className="h-3.5 w-3.5" />
                      </button>
                    </div>

                    {!vdiskReport || vdiskReport.disks.length === 0 ? (
                      <div className="mt-3 text-xs text-slate-500">{t("vdiskEmpty")}</div>
                    ) : (
                      <div className="mt-3 space-y-3">
                        {vdiskReport.disks.map((d) => (
                          <div
                            key={d.id}
                            className="rounded-xl border border-slate-200/80 bg-slate-50/70 p-3.5 text-xs dark:border-slate-800 dark:bg-slate-950/60"
                          >
                            <div className="flex flex-wrap items-start justify-between gap-3">
                              <div className="min-w-0">
                                <div className="flex flex-wrap items-center gap-2">
                                  <span className="font-bold text-sm">{d.name}</span>
                                  {d.is_in_use && (
                                    <span className="rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-amber-600 dark:text-amber-400">
                                      {t("lockedWarning")}
                                    </span>
                                  )}
                                </div>
                                <div className="mt-0.5 truncate font-mono text-[11px] text-slate-500">
                                  {d.path}
                                </div>
                              </div>

                              <div className="flex shrink-0 items-center gap-4">
                                <div className="text-right">
                                  <div className="font-bold text-sky-600 dark:text-sky-400">
                                    {t("vdiskPhysical")}: {formatBytes(d.allocated_bytes)}
                                  </div>
                                  <div className="text-[11px] text-slate-500">
                                    {t("vdiskLogical")}: {formatBytes(d.logical_bytes)}
                                  </div>
                                </div>
                                <button
                                  onClick={() => void handleCopyVdiskScript(d.id, d.compact_script)}
                                  className="flex items-center gap-1.5 rounded-lg bg-sky-500 px-3 py-1.5 font-semibold text-white hover:bg-sky-600"
                                >
                                  <Copy className="h-3.5 w-3.5" />
                                  {copiedVdiskId === d.id ? t("vdiskCopied") : t("vdiskCopyScript")}
                                </button>
                              </div>
                            </div>

                            <div className="mt-2 text-[11px] text-slate-600 dark:text-slate-300">
                              {locale === "zh-CN" ? d.safety_note_zh : d.safety_note}
                            </div>
                            <pre className="mt-2 overflow-x-auto rounded-lg bg-slate-900 px-3 py-2 font-mono text-[11px] text-emerald-300">
                              {d.compact_command}
                            </pre>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {auditTab === "ignore" && (
                <div className="space-y-2 text-xs">
                  {!appConfig || appConfig.ignore_paths.length === 0 ? (
                    <div className="py-8 text-center text-slate-500">{t("noIgnore")}</div>
                  ) : (
                    appConfig.ignore_paths.map((p) => (
                      <div
                        key={p}
                        className="flex items-center justify-between border-b border-slate-100 py-2 dark:border-slate-800"
                      >
                        <span className="font-mono">{p}</span>
                        <button
                          onClick={() => handleIgnorePath(p, true)}
                          className="rounded bg-rose-500/10 px-2.5 py-1 font-semibold text-rose-600"
                        >
                          {t("removeIgnore")}
                        </button>
                      </div>
                    ))
                  )}
                </div>
              )}

              {auditTab === "rules" && (
                <div className="space-y-4">
                  {rulesList.map((rf) => (
                    <div
                      key={rf.app_name}
                      className="rounded-xl border border-slate-200 p-3 dark:border-slate-800"
                    >
                      <div className="text-sm font-bold">
                        {locale === "zh-CN" ? rf.app_name_zh || rf.app_name : rf.app_name}
                        <span className="ml-2 text-xs font-normal text-slate-500">
                          ({rf.category})
                        </span>
                      </div>
                      <div className="mt-2 space-y-1.5 text-xs">
                        {rf.rules.map((r) => (
                          <div
                            key={r.id}
                            className="flex items-center justify-between text-slate-600 dark:text-slate-300"
                          >
                            <span>
                              <code className="mr-2 text-[11px] text-sky-500">{r.id}</code>
                              {locale === "zh-CN" ? r.title_zh || r.title : r.title}
                            </span>
                            <span className="rounded bg-slate-100 px-2 py-0.5 text-[10px] font-semibold uppercase dark:bg-slate-800">
                              {r.risk} · {r.delete_mode}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </main>

      {/* P0.4: Dry-Run Preview Modal */}
      {dryRunModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/60 p-6 backdrop-blur-xs">
          <div className="flex max-h-[80vh] w-full max-w-2xl flex-col rounded-2xl border border-slate-200 bg-white p-5 shadow-2xl dark:border-slate-800 dark:bg-slate-900">
            <div className="flex items-center justify-between border-b border-slate-200 pb-3 dark:border-slate-800">
              <h2 className="text-base font-bold">{t("dryRunModalTitle")}</h2>
              <button onClick={() => setDryRunModal(null)}>
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="my-3 flex-1 overflow-y-auto divide-y divide-slate-100 text-xs dark:divide-slate-800">
              {dryRunModal.outcomes.map((o, i) => (
                <div key={i} className="flex items-center justify-between gap-4 py-2">
                  <div className="min-w-0">
                    <div className="font-semibold">{o.rule_id}</div>
                    <div className="truncate font-mono text-[11px] text-slate-500">{o.path}</div>
                  </div>
                  <div className="shrink-0 text-right">
                    <span className="mr-2 rounded bg-slate-100 px-1.5 py-0.5 text-[10px] font-bold uppercase dark:bg-slate-800">
                      {o.actual_mode}
                    </span>
                    <span className="font-bold">{formatBytes(o.freed_bytes)}</span>
                  </div>
                </div>
              ))}
            </div>
            <div className="flex items-center justify-between border-t border-slate-200 pt-3 dark:border-slate-800">
              <div className="text-sm font-bold">
                {t("reclaimableTotal")}: {formatBytes(dryRunModal.total_freed_bytes)}
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => setDryRunModal(null)}
                  className="rounded-xl border border-slate-300 px-4 py-2 text-xs font-semibold dark:border-slate-700"
                >
                  {t("close")}
                </button>
                <button
                  disabled={isCleaning}
                  onClick={() => void handleClean(false)}
                  className="rounded-xl bg-sky-500 px-4 py-2 text-xs font-semibold text-white hover:bg-sky-600 disabled:opacity-40"
                >
                  {t("dryRunConfirmApply")}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function defaultDuplicateSelection(report: DuplicateReport): Set<string> {
  const sel = new Set<string>();
  for (const g of report.groups) {
    for (const e of g.entries) {
      if (!e.recommended_keep) {
        sel.add(e.path);
      }
    }
  }
  return sel;
}

function isPathEqualOrUnder(candidate: string, prefix: string): boolean {
  const c = candidate.replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
  const p = prefix.replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
  return Boolean(p) && (c === p || c.startsWith(`${p}/`));
}

export default App;
