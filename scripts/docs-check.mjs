#!/usr/bin/env node
/**
 * Zero-dependency documentation validator (Node >= 16).
 * Run from the repository root:  node scripts/docs-check.mjs
 * Exit 1 on any error.
 */
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const CONFIG = {
  docsRoot: "docs",
  overview: "00-overview.md",
  router: "AGENTS.md",
  skipDirs: new Set([
    ".git",
    "node_modules",
    "dist",
    "build",
    "out",
    "venv",
    ".venv",
    "vendor",
    "__pycache__",
    ".next",
    "target",
    ".wrangler",
  ]),
  extraDocs: [
    "README.md",
    "SECURITY.md",
    "mcp-server/README.md",
  ],
  extraDocDirs: [
    "marketplace",
  ],
  entryGlobs: [
    "src/*.ts",
    "mcp-server/index.mjs",
    "scripts/*.mjs",
    "tests/*.test.cjs",
    "static/frontend/src/App.tsx",
    "static/frontend/src/bridge.ts",
    "static/frontend/src/components/AuditLogModal.tsx",
    "static/frontend/src/components/FdaExportModal.tsx",
  ],
  pathExts: new Set([
    ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".md", ".json",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".sh", ".rs", ".go", ".c", ".h", ".cpp",
    ".hpp", ".ino", ".tf", ".sql", ".ipynb", ".txt",
  ]),
};

const ROOT = path.resolve(process.env.DOCS_CHECK_ROOT || process.cwd());
const DOCS = path.join(ROOT, CONFIG.docsRoot);
const OVERVIEW = CONFIG.overview;
const ROUTER = path.join(ROOT, CONFIG.router);

const errors = [];
const warnings = [];
let checked = 0;

const rel = (p) => path.relative(ROOT, p) || ".";
const fail = (rule, p, msg, line) =>
  errors.push(`${line ? `${rel(p)}:${line}` : rel(p)}: ${rule}: ${msg}`);
const warn = (rule, p, msg) => warnings.push(`${rel(p)}: ${rule}: ${msg}`);
const read = (p) => { try { return fs.readFileSync(p, "utf8"); } catch { return ""; } };
const skipped = (p) => p.split(path.sep).some((s) => CONFIG.skipDirs.has(s));

function walk(dir, ext) {
  if (!fs.existsSync(dir)) return [];
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (!CONFIG.skipDirs.has(e.name)) out.push(...walk(full, ext));
    } else if (e.name.endsWith(ext)) out.push(full);
  }
  return out.sort();
}

// ------------------------------------------------------------- rule 4: links
const LINK_RE = /\[[^\]]*\]\(\s*([^)\s]+)(?:\s+"[^"]*")?\s*\)/g;

function checkLinks(file, text) {
  checked++;
  for (const m of text.matchAll(LINK_RE)) {
    let target = m[1].trim();
    if (!target || /^(https?:\/\/|mailto:|#|<)/.test(target)) continue;
    target = target.split("#")[0].split("?")[0];
    if (!target) continue;
    const line = text.slice(0, m.index).split("\n").length;
    const cand = path.resolve(path.dirname(file), target);
    if (!fs.existsSync(cand) && !fs.existsSync(path.join(ROOT, target))) {
      fail("link", file, `broken relative link -> ${target}`, line);
    }
  }
}

// ----------------------------------------------------- rule 1: backtick paths
const TOKEN_RE = /`([^`\n]+)`/g;
const EXT = (tok) => path.extname(tok).toLowerCase();
const NON_PATH_PREFIX = /^(@|ari:|https?:\/\/|mailto:|#|\$|-|git |npm |pnpm |yarn |uv |pip |python3? |cargo |go |make |docker |pytest )/;

function looksLikePath(tok) {
  if (!tok || tok.length > 200) return false;
  if (NON_PATH_PREFIX.test(tok)) return false;
  if (/[<>]/.test(tok) || /\s/.test(tok)) return false;
  if (tok.includes("=") || tok.startsWith("/")) return false;
  if (tok.includes("*")) return null;
  return tok.includes("/") || CONFIG.pathExts.has(EXT(tok));
}

function expandBraces(pattern) {
  const m = pattern.match(/\{([^{}]*)\}/);
  if (!m) return [pattern];
  return m[1].split(",").flatMap((alt) =>
    expandBraces(pattern.slice(0, m.index) + alt + pattern.slice(m.index + m[0].length)));
}

function globToRegex(pattern) {
  let re = "";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === "*") {
      if (pattern[i + 1] === "*") { re += ".*"; i++; if (pattern[i + 1] === "/") i++; }
      else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`);
}

function globFiles(pattern) {
  const regex = globToRegex(pattern);
  const out = [];
  (function rec(dir) {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.isDirectory()) {
        if (!CONFIG.skipDirs.has(e.name)) rec(path.join(dir, e.name));
      } else {
        const r = path.relative(ROOT, path.join(dir, e.name)).split(path.sep).join("/");
        if (regex.test(r)) out.push(r);
      }
    }
  })(ROOT);
  return out;
}

function checkPaths(file, text) {
  for (const m of text.matchAll(TOKEN_RE)) {
    const tok = m[1].trim().replace(/[()[\]{},;:]+$/, "");
    const kind = looksLikePath(tok);
    if (kind === null) continue;
    if (!kind) continue;
    if (fs.existsSync(path.join(ROOT, tok)) || fs.existsSync(path.join(path.dirname(file), tok))) continue;
    fail("path", file, `backticked path not on disk -> ${tok}`,
      text.slice(0, m.index).split("\n").length);
  }
}

// --------------------------------------------- rule 2/3: overview + backlink
const BACKLINK_RE = /\[[^\]]*\]\(((?:\.\.\/|\.\/)*)00-overview\.md\)/;

function checkFolder(folder) {
  const ov = path.join(folder, OVERVIEW);
  if (!fs.existsSync(ov)) { fail("overview", folder, `missing ${OVERVIEW}`); return; }
  const ovText = read(ov);
  const linked = new Set([...ovText.matchAll(LINK_RE)]
    .map((m) => path.resolve(folder, m[1].trim().split("#")[0])));
  for (const e of fs.readdirSync(folder, { withFileTypes: true })) {
    if (!e.isFile() || !e.name.endsWith(".md") || e.name === OVERVIEW) continue;
    if (!linked.has(path.resolve(folder, e.name))) {
      fail("overview", ov, `does not link ${e.name}`);
    }
  }
}

function checkBacklink(file) {
  const head = read(file).split("\n").slice(0, 15).join("\n");
  if (!BACKLINK_RE.test(head)) fail("backlink", file, "missing top backlink to 00-overview.md");
}

// ---------------------------------------------------- rule 5: reverse coverage
function checkReverseCoverage(allText) {
  for (const pattern of CONFIG.entryGlobs) {
    for (const pat of expandBraces(pattern)) {
      for (const key of globFiles(pat)) {
        if (!allText.includes(key)) fail("reverse-coverage", key, "entry point referenced by no doc");
      }
    }
  }
}

function main() {
  if (!fs.existsSync(DOCS)) {
    console.error(`docs-check: ${CONFIG.docsRoot} does not exist`);
    return 1;
  }
  const docFiles = walk(DOCS, ".md");
  const extraDocFiles = [
    ...CONFIG.extraDocs.map((f) => path.join(ROOT, f)).filter((f) => fs.existsSync(f)),
    ...CONFIG.extraDocDirs.flatMap((d) => walk(path.join(ROOT, d), ".md")),
  ];
  const checkedDocs = [...docFiles, ...extraDocFiles];
  const sources = [...checkedDocs, ...(fs.existsSync(ROUTER) ? [ROUTER] : [])];
  const texts = new Map();
  for (const f of sources) { const t = read(f); texts.set(f, t); checkLinks(f, t); }
  for (const f of checkedDocs) checkPaths(f, texts.get(f));
  if (fs.existsSync(ROUTER)) checkPaths(ROUTER, texts.get(ROUTER));
  else warn("router", ROUTER, "router file missing");

  const folders = fs.readdirSync(DOCS, { withFileTypes: true })
    .filter((e) => e.isDirectory() && /^\d{2,}-/.test(e.name) && !CONFIG.skipDirs.has(e.name))
    .map((e) => path.join(DOCS, e.name)).sort();
  for (const folder of folders) {
    checkFolder(folder);
    for (const f of walk(folder, ".md")) {
      if (path.basename(f) !== OVERVIEW) checkBacklink(f);
    }
  }

  checkReverseCoverage([...texts.values()].join("\n"));

  for (const w of warnings) console.error(`warning: ${w}`);
  for (const e of errors) console.error(`error: ${e}`);
  console.log(`docs-check: ${checkedDocs.length} doc files (${docFiles.length} in docs/, ${extraDocFiles.length} top-level/marketplace), ${folders.length} subjects, ` +
    `${errors.length} errors, ${warnings.length} warnings`);
  return errors.length ? 1 : 0;
}

process.exit(main());
