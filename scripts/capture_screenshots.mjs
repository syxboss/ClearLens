import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import puppeteer from "puppeteer-core";

const DIST_DIR = "/app/apps/desktop/dist";
const OUT_DIR = "/out";
const CLI_TXT_PATH = "/tmp/cli_demo_output.txt";

fs.mkdirSync(OUT_DIR, { recursive: true });

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".json": "application/json",
};

function startServer() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const urlPath = (req.url || "/").split("?")[0];
      const rel = urlPath === "/" ? "/index.html" : urlPath;
      const fullPath = path.join(DIST_DIR, rel);
      const target = fs.existsSync(fullPath) && fs.statSync(fullPath).isFile()
        ? fullPath
        : path.join(DIST_DIR, "index.html");
      const ext = path.extname(target);
      res.writeHead(200, { "Content-Type": MIME[ext] || "application/octet-stream" });
      fs.createReadStream(target).pipe(res);
    });
    server.listen(4173, "127.0.0.1", () => resolve(server));
  });
}

function findChromeExecutable() {
  for (const cand of [
    process.env.CHROME_BIN,
    "/usr/bin/chromium-browser",
    "/usr/bin/chromium",
    "/usr/bin/google-chrome",
  ]) {
    if (cand && fs.existsSync(cand)) return cand;
  }
  throw new Error("Chromium executable not found in container");
}

function escapeXml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function generateCliSvg() {
  const raw = fs.existsSync(CLI_TXT_PATH)
    ? fs.readFileSync(CLI_TXT_PATH, "utf8")
    : "$ clens scan --mode smart\nVALID: 6 rule packs (39 rules)";
  const lines = raw.trimEnd().split(/\r?\n/).slice(0, 32);
  const lineHeight = 20;
  const paddingTop = 58;
  const height = Math.max(300, paddingTop + lines.length * lineHeight + 28);
  const width = 980;

  const textSpans = lines
    .map((line, i) => {
      const y = paddingTop + i * lineHeight;
      const fill = line.startsWith("$ ")
        ? "#38bdf8"
        : line.includes("VALID:") || line.includes("Summary")
          ? "#34d399"
          : line.includes("SAFE")
            ? "#4ade80"
            : line.includes("RECREATABLE")
              ? "#fbbf24"
              : line.includes("REVIEW")
                ? "#fb7185"
                : "#cbd5e1";
      return `<text x="24" y="${y}" fill="${fill}" xml:space="preserve">${escapeXml(line)}</text>`;
    })
    .join("\n    ");

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
  <rect width="${width}" height="${height}" rx="14" fill="#0b1220" stroke="#1e293b" stroke-width="1.5" />
  <rect width="${width}" height="36" rx="14" fill="#131c31" />
  <rect y="22" width="${width}" height="14" fill="#131c31" />
  <circle cx="22" cy="18" r="6" fill="#ff5f56" />
  <circle cx="42" cy="18" r="6" fill="#ffbd2e" />
  <circle cx="62" cy="18" r="6" fill="#27c93f" />
  <text x="${width / 2}" y="22" text-anchor="middle" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="12" fill="#94a3b8">clens — zsh (ClearLens CLI)</text>
  <g font-family="ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace" font-size="13">
    ${textSpans}
  </g>
</svg>
`;
  fs.writeFileSync(path.join(OUT_DIR, "cli-demo.svg"), svg, "utf8");
}

const SHOT_MATRIX = [
  { file: "en-smart-clean.png", query: "?lang=en&tab=smart&pro=1&theme=dark" },
  { file: "en-deep-clean.png", query: "?lang=en&tab=deep&cat=dev_ai&pro=1&theme=dark" },
  { file: "en-space-lens.png", query: "?lang=en&tab=lens&theme=dark" },
  { file: "zh-smart-clean.png", query: "?lang=zh-CN&tab=smart&pro=1&theme=dark" },
  { file: "zh-deep-clean.png", query: "?lang=zh-CN&tab=deep&cat=dev_ai&pro=1&theme=dark" },
  { file: "zh-space-lens.png", query: "?lang=zh-CN&tab=lens&theme=dark" },
];

async function main() {
  generateCliSvg();
  const server = await startServer();
  const browser = await puppeteer.launch({
    executablePath: findChromeExecutable(),
    headless: true,
    args: [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu",
    ],
  });

  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 820, deviceScaleFactor: 2 });

    for (const item of SHOT_MATRIX) {
      await page.goto(`http://127.0.0.1:4173/${item.query}`, { waitUntil: "networkidle0" });
      await page.evaluate(async () => {
        await document.fonts.ready;
        await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
      });
      await new Promise((r) => setTimeout(r, 250));
      await page.screenshot({ path: path.join(OUT_DIR, item.file) });
      console.log(`Captured ${item.file}`);
    }
  } finally {
    await browser.close();
    server.close();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
