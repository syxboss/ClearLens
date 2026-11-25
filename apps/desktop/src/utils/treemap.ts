import type { RiskLevel, ScanHit, SpaceNode } from "../types";

export interface TreemapRect {
  node: SpaceNode;
  x: number;
  y: number;
  w: number;
  h: number;
  color: string;
}

const PALETTE = [
  "#0ea5e9",
  "#14b8a6",
  "#6366f1",
  "#f59e0b",
  "#ec4899",
  "#8b5cf6",
  "#10b981",
  "#f97316",
];

/**
 * Computes a Squarified Treemap layout inside [0, 0, width, height].
 * Guarantees non-overlapping bounded rectangles whose areas stay proportional to allocated_bytes.
 */
export function computeSquarifiedTreemap(
  children: SpaceNode[],
  width: number,
  height: number
): TreemapRect[] {
  if (width <= 2 || height <= 2) return [];
  const items = children
    .filter((c) => c.allocated_bytes > 0)
    .slice()
    .sort((a, b) => b.allocated_bytes - a.allocated_bytes);
  const total = items.reduce((acc, item) => acc + item.allocated_bytes, 0);
  if (total <= 0) return [];

  const totalArea = width * height;
  const scaled = items.map((node, index) => ({
    node,
    area: (node.allocated_bytes / total) * totalArea,
    color: node.is_synthetic_other ? "#64748b" : PALETTE[index % PALETTE.length],
  }));

  const out: TreemapRect[] = [];
  squarify(scaled, [], { x: 0, y: 0, w: width, h: height }, out);
  return out;
}

interface Box {
  x: number;
  y: number;
  w: number;
  h: number;
}

interface ScaledItem {
  node: SpaceNode;
  area: number;
  color: string;
}

function squarify(
  remaining: ScaledItem[],
  row: ScaledItem[],
  box: Box,
  out: TreemapRect[]
) {
  if (remaining.length === 0) {
    layoutRow(row, box, out);
    return;
  }
  const shortSide = Math.min(box.w, box.h);
  if (shortSide <= 0) return;

  const next = remaining[0];
  if (row.length === 0) {
    squarify(remaining.slice(1), [next], box, out);
    return;
  }

  const withNext = [...row, next];
  if (worstAspect(withNext, shortSide) <= worstAspect(row, shortSide)) {
    squarify(remaining.slice(1), withNext, box, out);
  } else {
    const nextBox = layoutRow(row, box, out);
    squarify(remaining, [], nextBox, out);
  }
}

function worstAspect(row: ScaledItem[], side: number): number {
  const sum = row.reduce((a, b) => a + b.area, 0);
  if (sum <= 0 || side <= 0) return Infinity;
  let maxArea = 0;
  let minArea = Infinity;
  for (const item of row) {
    if (item.area > maxArea) maxArea = item.area;
    if (item.area < minArea) minArea = item.area;
  }
  const s2 = side * side;
  const sum2 = sum * sum;
  return Math.max((s2 * maxArea) / sum2, sum2 / (s2 * minArea));
}

function layoutRow(row: ScaledItem[], box: Box, out: TreemapRect[]): Box {
  if (row.length === 0) return box;
  const sum = row.reduce((a, b) => a + b.area, 0);
  if (sum <= 0) return box;

  if (box.w >= box.h) {
    const rowWidth = Math.min(box.w, sum / Math.max(box.h, 1));
    let cy = box.y;
    for (const item of row) {
      const h = (item.area / sum) * box.h;
      out.push({
        node: item.node,
        x: box.x,
        y: cy,
        w: rowWidth,
        h,
        color: item.color,
      });
      cy += h;
    }
    return { x: box.x + rowWidth, y: box.y, w: Math.max(0, box.w - rowWidth), h: box.h };
  } else {
    const rowHeight = Math.min(box.h, sum / Math.max(box.w, 1));
    let cx = box.x;
    for (const item of row) {
      const w = (item.area / sum) * box.w;
      out.push({
        node: item.node,
        x: cx,
        y: box.y,
        w,
        h: rowHeight,
        color: item.color,
      });
      cx += w;
    }
    return { x: box.x, y: box.y + rowHeight, w: box.w, h: Math.max(0, box.h - rowHeight) };
  }
}

/**
 * Computes initial selected hit IDs from a ScanReport.
 * Safety invariant: `review_required` items are NEVER auto-selected by default.
 */
export function computeDefaultSelectedIds(hits: ScanHit[]): Set<string> {
  const selected = new Set<string>();
  for (const h of hits) {
    if (h.risk !== "review_required" && h.default_checked) {
      selected.add(h.id);
    }
  }
  return selected;
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let val = bytes;
  let idx = 0;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx++;
  }
  return idx === 0 ? `${bytes} B` : `${val.toFixed(2)} ${units[idx]}`;
}

export function isRiskAutoSelectable(risk: RiskLevel): boolean {
  return risk !== "review_required";
}

/**
 * UI-layer Anti-Wipe Safety Guard for duplicate groups:
 * Toggles a file path for deletion ONLY if at least 1 copy in `groupPaths` remains unselected.
 */
export function toggleDuplicateDeletion(
  selectedPaths: Set<string>,
  groupPaths: string[],
  targetPath: string
): Set<string> {
  const next = new Set(selectedPaths);
  if (next.has(targetPath)) {
    next.delete(targetPath);
    return next;
  }
  const currentlySelectedInGroup = groupPaths.filter((p) => next.has(p)).length;
  if (currentlySelectedInGroup + 1 >= groupPaths.length) {
    // Hard UI lock: never permit selecting every copy in a group
    return selectedPaths;
  }
  next.add(targetPath);
  return next;
}
