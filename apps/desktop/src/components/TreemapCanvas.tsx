import React, { useEffect, useMemo, useRef, useState } from "react";
import type { SpaceNode } from "../types";
import { computeSquarifiedTreemap, formatBytes, type TreemapRect } from "../utils/treemap";

interface TreemapCanvasProps {
  node: SpaceNode;
  hoveredPath: string | null;
  onHoverPath: (path: string | null) => void;
  onDrillDown: (node: SpaceNode) => void;
}

export const TreemapCanvas: React.FC<TreemapCanvasProps> = ({
  node,
  hoveredPath,
  onHoverPath,
  onDrillDown,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [size, setSize] = useState({ width: 520, height: 340 });
  const [tooltip, setTooltip] = useState<{ rect: TreemapRect; x: number; y: number } | null>(null);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const update = () => {
      const r = el.getBoundingClientRect();
      if (r.width > 10 && r.height > 10) {
        setSize({ width: Math.floor(r.width), height: Math.floor(r.height) });
      }
    };
    update();
    const obs = new ResizeObserver(update);
    obs.observe(el);
    return () => obs.disconnect();
  }, []);

  const rects = useMemo(
    () => computeSquarifiedTreemap(node.children, size.width, size.height),
    [node.children, size.width, size.height]
  );

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = size.width * dpr;
    canvas.height = size.height * dpr;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, size.width, size.height);

    for (const r of rects) {
      const pad = 1.5;
      const rx = r.x + pad;
      const ry = r.y + pad;
      const rw = Math.max(0, r.w - pad * 2);
      const rh = Math.max(0, r.h - pad * 2);
      if (rw < 1 || rh < 1) continue;

      const isHovered = hoveredPath === r.node.path;
      ctx.fillStyle = r.color;
      ctx.globalAlpha = isHovered ? 0.96 : 0.82;
      ctx.beginPath();
      ctx.roundRect(rx, ry, rw, rh, 6);
      ctx.fill();

      if (isHovered) {
        ctx.globalAlpha = 1;
        ctx.strokeStyle = "#ffffff";
        ctx.lineWidth = 2;
        ctx.stroke();
      }

      if (rw > 64 && rh > 34) {
        ctx.globalAlpha = 1;
        ctx.fillStyle = "#ffffff";
        ctx.font = "600 12px -apple-system, BlinkMacSystemFont, sans-serif";
        const label = truncateText(ctx, r.node.name, rw - 14);
        ctx.fillText(label, rx + 7, ry + 18);

        if (rh > 48) {
          ctx.fillStyle = "rgba(255,255,255,0.88)";
          ctx.font = "500 11px -apple-system, BlinkMacSystemFont, sans-serif";
          ctx.fillText(formatBytes(r.node.allocated_bytes), rx + 7, ry + 34);
        }
      }
    }
  }, [rects, size.width, size.height, hoveredPath]);

  const findHit = (clientX: number, clientY: number): { rect: TreemapRect; lx: number; ly: number } | null => {
    const canvas = canvasRef.current;
    if (!canvas) return null;
    const bounds = canvas.getBoundingClientRect();
    const lx = clientX - bounds.left;
    const ly = clientY - bounds.top;
    const hit = rects.find((r) => lx >= r.x && lx <= r.x + r.w && ly >= r.y && ly <= r.y + r.h);
    return hit ? { rect: hit, lx, ly } : null;
  };

  return (
    <div ref={containerRef} className="relative h-full min-h-[320px] w-full select-none overflow-hidden rounded-xl bg-slate-100/80 dark:bg-slate-900/70">
      <canvas
        ref={canvasRef}
        style={{ width: size.width, height: size.height }}
        className="block cursor-pointer"
        onMouseMove={(e) => {
          const hit = findHit(e.clientX, e.clientY);
          if (hit) {
            onHoverPath(hit.rect.node.path);
            setTooltip({ rect: hit.rect, x: hit.lx, y: hit.ly });
          } else {
            onHoverPath(null);
            setTooltip(null);
          }
        }}
        onMouseLeave={() => {
          onHoverPath(null);
          setTooltip(null);
        }}
        onClick={(e) => {
          const hit = findHit(e.clientX, e.clientY);
          if (
            hit &&
            hit.rect.node.is_dir &&
            (hit.rect.node.children.length > 0 || hit.rect.node.has_more_children)
          ) {
            onDrillDown(hit.rect.node);
          }
        }}
      />
      {tooltip && (
        <div
          className="pointer-events-none absolute z-20 rounded-lg border border-slate-200 bg-white/95 px-3 py-2 text-xs shadow-lg backdrop-blur dark:border-slate-700 dark:bg-slate-800/95"
          style={{
            left: Math.min(tooltip.x + 12, Math.max(8, size.width - 210)),
            top: Math.min(tooltip.y + 12, Math.max(8, size.height - 76)),
          }}
        >
          <div className="max-w-[190px] truncate font-semibold text-slate-900 dark:text-slate-100">
            {tooltip.rect.node.name}
          </div>
          <div className="mt-0.5 text-slate-600 dark:text-slate-300">
            {formatBytes(tooltip.rect.node.allocated_bytes)} · {tooltip.rect.node.file_count.toLocaleString()} files
          </div>
          {node.allocated_bytes > 0 && (
            <div className="text-[11px] text-sky-600 dark:text-sky-400">
              {((tooltip.rect.node.allocated_bytes / node.allocated_bytes) * 100).toFixed(1)}%
            </div>
          )}
        </div>
      )}
    </div>
  );
};

function truncateText(ctx: CanvasRenderingContext2D, text: string, maxWidth: number): string {
  if (maxWidth <= 0) return "";
  if (ctx.measureText(text).width <= maxWidth) return text;
  let lo = 1;
  let hi = text.length;
  let best = 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (ctx.measureText(`${text.slice(0, mid)}…`).width <= maxWidth) {
      best = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return `${text.slice(0, best)}…`;
}
