import { describe, expect, it } from "vitest";
import {
  buildDemoScanReport,
  DEMO_DUPLICATES,
  DEMO_LENS_REPORT,
  DEMO_UNINSTALLER,
  DEMO_VDISKS,
} from "../api/bridge";
import { MESSAGES } from "../i18n";
import type { ScanHit, SpaceNode } from "../types";
import {
  computeDefaultSelectedIds,
  computeSquarifiedTreemap,
  formatBytes,
  toggleDuplicateDeletion,
} from "../utils/treemap";

describe("ClearLens Frontend Core Logic", () => {
  it("computes bounded proportional Squarified Treemap rectangles", () => {
    const children: SpaceNode[] = [
      { name: "node_modules", path: "/a", allocated_bytes: 600, file_count: 100, is_dir: true, is_synthetic_other: false, children: [] },
      { name: "target", path: "/b", allocated_bytes: 300, file_count: 50, is_dir: true, is_synthetic_other: false, children: [] },
      { name: "logs", path: "/c", allocated_bytes: 100, file_count: 10, is_dir: true, is_synthetic_other: false, children: [] },
    ];
    const rects = computeSquarifiedTreemap(children, 1000, 500);
    expect(rects).toHaveLength(3);

    const totalArea = rects.reduce((sum, r) => sum + r.w * r.h, 0);
    expect(totalArea).toBeCloseTo(1000 * 500, 1);

    for (const r of rects) {
      expect(r.x).toBeGreaterThanOrEqual(0);
      expect(r.y).toBeGreaterThanOrEqual(0);
      expect(r.x + r.w).toBeLessThanOrEqual(1000.01);
      expect(r.y + r.h).toBeLessThanOrEqual(500.01);
    }
  });

  it("never auto-selects review_required hits by default", () => {
    const hits: ScanHit[] = [
      {
        id: "1",
        rule_id: "system.temp",
        category: "system",
        app_name: "OS",
        app_name_zh: "系统",
        title: "Temp",
        title_zh: "临时",
        risk: "safe",
        default_checked: true,
        delete_mode: "permanent",
        requires_elevation: false,
        path: "/tmp/a",
        allocated_bytes: 1024,
        file_count: 1,
        last_modified_ts: 0,
        impact_note: "",
        impact_note_zh: "",
        locked_by_process: null,
        native_command: null,
      },
      {
        id: "2",
        rule_id: "system.downloads_old_installers",
        category: "system",
        app_name: "OS",
        app_name_zh: "系统",
        title: "Old DMG",
        title_zh: "旧安装包",
        risk: "review_required",
        default_checked: true, // Even if malformed true, UI safety guard must skip!
        delete_mode: "trash",
        requires_elevation: false,
        path: "/Downloads/a.dmg",
        allocated_bytes: 5000,
        file_count: 1,
        last_modified_ts: 0,
        impact_note: "",
        impact_note_zh: "",
        locked_by_process: null,
        native_command: null,
      },
    ];
    const selected = computeDefaultSelectedIds(hits);
    expect(selected.has("1")).toBe(true);
    expect(selected.has("2")).toBe(false);
  });

  it("maintains full key parity between zh-CN and en dictionaries", () => {
    const zhKeys = Object.keys(MESSAGES["zh-CN"]).sort();
    const enKeys = Object.keys(MESSAGES.en).sort();
    expect(zhKeys).toEqual(enKeys);
  });

  it("formats byte sizes cleanly", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1024)).toBe("1.00 KB");
    expect(formatBytes(1024 * 1024 * 2)).toBe("2.00 MB");
  });

  it("ensures demo bridge data respects review_required safety defaults", () => {
    const demo = buildDemoScanReport(null);
    expect(demo.hits.length).toBeGreaterThan(5);
    const selected = computeDefaultSelectedIds(demo.hits);
    for (const h of demo.hits) {
      if (h.risk === "review_required") {
        expect(selected.has(h.id)).toBe(false);
      }
    }
    expect(DEMO_LENS_REPORT.root.allocated_bytes).toBeGreaterThan(0);
    expect(DEMO_LENS_REPORT.cold_files.length).toBeGreaterThan(0);
    expect(DEMO_DUPLICATES.groups.length).toBeGreaterThan(0);
    expect(DEMO_UNINSTALLER.orphans.length).toBeGreaterThan(0);
    expect(DEMO_VDISKS.disks.length).toBeGreaterThan(0);
    for (const d of DEMO_VDISKS.disks) {
      expect(d.allocated_bytes).toBeLessThanOrEqual(d.logical_bytes);
      expect(d.compact_script.length).toBeGreaterThan(10);
    }
  });

  it("enforces anti-wipe lock in duplicate deletion toggles (never selects all copies)", () => {
    const groupPaths = ["/a/movie.mp4", "/b/movie_copy1.mp4", "/c/movie_copy2.mp4"];
    let selected = new Set<string>(["/b/movie_copy1.mp4", "/c/movie_copy2.mp4"]);

    // Attempting to select the last surviving original MUST be blocked!
    const blocked = toggleDuplicateDeletion(selected, groupPaths, "/a/movie.mp4");
    expect(blocked.has("/a/movie.mp4")).toBe(false);
    expect(blocked.size).toBe(2);

    // Deselecting one copy works and then allows selecting another copy while keeping >= 1
    selected = toggleDuplicateDeletion(selected, groupPaths, "/c/movie_copy2.mp4");
    expect(selected.size).toBe(1);
    selected = toggleDuplicateDeletion(selected, groupPaths, "/a/movie.mp4");
    expect(selected.has("/a/movie.mp4")).toBe(true);
    expect(selected.size).toBe(2);
  });
});
