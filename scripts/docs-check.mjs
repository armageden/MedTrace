#!/usr/bin/env node
/**
 * Zero-dependency documentation validator (Node >= 16).
 * Run from the repository root:  node scripts/docs-check.mjs [--strict-listing]
 * Exit 1 on any error.
 */
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";

export const CONFIG = {
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
    "manifest.yml",
    "package.json",
    "static/frontend/package.json",
    ".github/workflows/*.yml",
    "src/*.ts",
    "mcp-server/index.mjs",
    "scripts/*.mjs",
    "scripts/*.sh",
    "tests/*.test.*",
    "static/frontend/src/**/*.ts",
    "static/frontend/src/**/*.tsx",
  ],
  pathExts: new Set([
    ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".md", ".json",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".sh", ".rs", ".go", ".c", ".h", ".cpp",
    ".hpp", ".ino", ".tf", ".sql", ".ipynb", ".txt",
  ]),
};

export const STRICT_LISTING_RE = /\[CONFIGURE BEFORE LISTING[^\n\]]*\]?/g;

const LINK_RE = /\[[^\]]*\]\(\s*([^)\s]+)(?:\s+(?:"[^"]*"|'[^']*'))?\s*\)/g;
const TOKEN_RE = /`([^`\n]+)`/g;
const NON_PATH_PREFIX = /^(@|ari:|https?:\/\/|mailto:|#|\$|-|git |npm |pnpm |yarn |uv |pip |python3? |cargo |go |make |docker |pytest )/;
const BACKLINK_RE = /\[[^\]]*\]\(((?:\.\.\/|\.\/)*)00-overview\.md\)/;

function readText(filePath) {
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch {
    return "";
  }
}

function walk(dir, ext) {
  if (!fs.existsSync(dir)) return [];
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!CONFIG.skipDirs.has(entry.name)) out.push(...walk(full, ext));
    } else if (entry.name.endsWith(ext)) {
      out.push(full);
    }
  }
  return out.sort();
}

function isInsideRoot(rootDir, candidate) {
  const relPath = path.relative(rootDir, candidate);
  return relPath === "" || (!relPath.startsWith("..") && !path.isAbsolute(relPath));
}

/**
 * Replaces fenced code block contents with empty lines so line numbers stay
 * intact while ignoring code examples during link and heading extraction.
 */
export function stripFencedCodeBlocks(text) {
  const lines = String(text ?? "").split(/\r?\n/);
  let fenceChar = null;
  let fenceLen = 0;

  return lines
    .map((line) => {
      if (!fenceChar) {
        const openMatch = line.match(/^ {0,3}(`{3,}|~{3,})(.*)$/);
        if (openMatch) {
          const marker = openMatch[1];
          const info = openMatch[2] || "";
          // CommonMark disallows backticks in backtick-fence info strings.
          if (marker[0] === "~" || !info.includes("`")) {
            fenceChar = marker[0];
            fenceLen = marker.length;
            return "";
          }
        }
        return line;
      }

      const closeMatch = line.match(/^ {0,3}(`{3,}|~{3,})[ \t]*$/);
      if (closeMatch && closeMatch[1][0] === fenceChar && closeMatch[1].length >= fenceLen) {
        fenceChar = null;
        fenceLen = 0;
      }
      return "";
    })
    .join("\n");
}

function stripInlineEmphasis(segment) {
  return segment
    .replace(/<[^>]+>/g, "")
    .replace(/\\([!"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~])/g, "$1")
    .replace(/(?<![\p{L}\p{N}])_+([^\s_](?:[^_]*[^\s_])?)_+(?![\p{L}\p{N}])/gu, "$1");
}

/**
 * Converts a Markdown heading title into its GitHub anchor slug.
 */
export function slugifyHeading(headingText) {
  let plain = String(headingText ?? "")
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/!\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/\[([^\]]+)\]\[[^\]]*\]/g, "$1");

  // Preserve underscores inside inline code spans while stripping outer backticks.
  let normalized = "";
  let cursor = 0;
  for (const m of plain.matchAll(/(`+)([\s\S]*?)\1/g)) {
    normalized += stripInlineEmphasis(plain.slice(cursor, m.index));
    normalized += m[2];
    cursor = m.index + m[0].length;
  }
  normalized += stripInlineEmphasis(plain.slice(cursor));

  return normalized
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{M}\p{N}_ -]/gu, "")
    .replace(/ /g, "-");
}

/**
 * Extracts GitHub-style heading anchor slugs from a Markdown document,
 * applying `-1`, `-2`, ... suffixes to duplicate headings.
 */
export function extractHeadingSlugs(text) {
  const stripped = stripFencedCodeBlocks(text);
  const slugs = new Set();
  const counts = new Map();

  for (const line of stripped.split("\n")) {
    const atx = line.match(/^ {0,3}(#{1,6})(?:[ \t]+(.*?))?[ \t]*$/);
    if (atx && atx[2]) {
      const rawHeading = atx[2].replace(/[ \t]+#+[ \t]*$/, "").trim();
      if (rawHeading) {
        const base = slugifyHeading(rawHeading);
        if (base) {
          let candidate = base;
          let n = counts.get(base) || 0;
          while (slugs.has(candidate)) {
            n += 1;
            candidate = `${base}-${n}`;
          }
          counts.set(base, n);
          slugs.add(candidate);
        }
      }
    }

    for (const m of line.matchAll(/<(?:a|h[1-6]|span|div)\b[^>]*\b(?:id|name)=["']([^"']+)["'][^>]*>/gi)) {
      const id = m[1].trim();
      if (id) slugs.add(id);
    }
  }

  return slugs;
}

function getHeadingSlugs(filePath, headingCache) {
  let slugs = headingCache.get(filePath);
  if (!slugs) {
    slugs = extractHeadingSlugs(readText(filePath));
    headingCache.set(filePath, slugs);
  }
  return slugs;
}

function decodeFragment(fragment) {
  try {
    return decodeURIComponent(fragment);
  } catch {
    return fragment;
  }
}

// ------------------------------------------------------------- rule 4: links
function checkLinks(file, text, ctx) {
  ctx.checked++;
  const stripped = stripFencedCodeBlocks(text);
  for (const m of stripped.matchAll(LINK_RE)) {
    const rawTarget = m[1].trim();
    if (!rawTarget || /^(https?:\/\/|mailto:|tel:|data:|<)/i.test(rawTarget)) continue;

    const line = stripped.slice(0, m.index).split("\n").length;
    const hashIdx = rawTarget.indexOf("#");
    const pathAndQuery = hashIdx === -1 ? rawTarget : rawTarget.slice(0, hashIdx);
    const fragment = hashIdx === -1 ? "" : rawTarget.slice(hashIdx + 1);
    const targetPath = pathAndQuery.split("?")[0];

    if (!targetPath) {
      if (fragment && file.toLowerCase().endsWith(".md")) {
        const slugs = getHeadingSlugs(file, ctx.headingCache);
        const decoded = decodeFragment(fragment);
        if (!slugs.has(decoded) && !slugs.has(fragment)) {
          ctx.fail("link-anchor", file, `broken anchor link -> ${rawTarget}`, line);
        }
      }
      continue;
    }

    const cand = path.resolve(path.dirname(file), targetPath);
    if (!isInsideRoot(ctx.root, cand)) {
      ctx.fail("link", file, `relative link escapes repository root -> ${rawTarget}`, line);
      continue;
    }
    if (!fs.existsSync(cand)) {
      ctx.fail("link", file, `broken relative link -> ${targetPath}`, line);
      continue;
    }

    if (fragment && cand.toLowerCase().endsWith(".md")) {
      let isFile = false;
      try {
        isFile = fs.statSync(cand).isFile();
      } catch {
        isFile = false;
      }
      if (isFile) {
        const slugs = getHeadingSlugs(cand, ctx.headingCache);
        const decoded = decodeFragment(fragment);
        if (!slugs.has(decoded) && !slugs.has(fragment)) {
          ctx.fail("link-anchor", file, `broken anchor link -> ${rawTarget}`, line);
        }
      }
    }
  }
}

// ----------------------------------------------------- rule 1: backtick paths
const EXT = (tok) => path.extname(tok).toLowerCase();

/**
 * Classifies whether a backticked inline token represents a file path.
 * Returns `null` for wildcard patterns that cannot be verified on disk.
 */
export function looksLikePath(tok) {
  if (!tok || tok.length > 200) return false;
  if (NON_PATH_PREFIX.test(tok)) return false;
  if (/[<>]/.test(tok) || /\s/.test(tok)) return false;
  if (tok.includes("=") || tok.startsWith("/")) return false;
  if (tok.includes("*")) return null;
  return tok.includes("/") || CONFIG.pathExts.has(EXT(tok));
}

/**
 * Expands brace expressions such as `{a,b}` into concrete glob patterns.
 */
export function expandBraces(pattern) {
  const m = pattern.match(/\{([^{}]*)\}/);
  if (!m) return [pattern];
  return m[1].split(",").flatMap((alt) =>
    expandBraces(pattern.slice(0, m.index) + alt + pattern.slice(m.index + m[0].length)));
}

/**
 * Compiles a simplified glob pattern (`*`, `**`, `?`) into a RegExp.
 */
export function globToRegex(pattern) {
  let re = "";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === "*") {
      if (pattern[i + 1] === "*") {
        re += ".*";
        i++;
        if (pattern[i + 1] === "/") i++;
      } else {
        re += "[^/]*";
      }
    } else if (c === "?") {
      re += "[^/]";
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
  }
  return new RegExp(`^${re}$`);
}

/**
 * Returns sorted repository-relative paths matching a glob pattern.
 */
export function globFiles(pattern, rootDir = process.cwd()) {
  const resolvedRoot = path.resolve(rootDir);
  const regex = globToRegex(pattern);
  const out = [];
  (function rec(dir) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.isDirectory()) {
        if (!CONFIG.skipDirs.has(e.name)) rec(path.join(dir, e.name));
      } else {
        const r = path.relative(resolvedRoot, path.join(dir, e.name)).split(path.sep).join("/");
        if (regex.test(r)) out.push(r);
      }
    }
  })(resolvedRoot);
  return out.sort();
}

function checkPaths(file, text, ctx) {
  const stripped = stripFencedCodeBlocks(text);
  for (const m of stripped.matchAll(TOKEN_RE)) {
    const tok = m[1].trim().replace(/[()[\]{},;:]+$/, "");
    const kind = looksLikePath(tok);
    if (kind === null || !kind) continue;

    const rootCand = path.resolve(ctx.root, tok);
    const dirCand = path.resolve(path.dirname(file), tok);
    const rootOk = isInsideRoot(ctx.root, rootCand) && fs.existsSync(rootCand);
    const dirOk = isInsideRoot(ctx.root, dirCand) && fs.existsSync(dirCand);
    if (rootOk || dirOk) continue;

    ctx.fail("path", file, `backticked path not on disk -> ${tok}`,
      stripped.slice(0, m.index).split("\n").length);
  }
}

// --------------------------------------------- rule 2/3: overview + backlink
function checkFolder(folder, ctx) {
  const ov = path.join(folder, CONFIG.overview);
  if (!fs.existsSync(ov)) {
    ctx.fail("overview", folder, `missing ${CONFIG.overview}`);
    return;
  }
  const ovText = stripFencedCodeBlocks(readText(ov));
  const linked = new Set([...ovText.matchAll(LINK_RE)]
    .map((m) => path.resolve(folder, m[1].trim().split("#")[0].split("?")[0])));
  for (const e of fs.readdirSync(folder, { withFileTypes: true })) {
    if (!e.isFile() || !e.name.endsWith(".md") || e.name === CONFIG.overview) continue;
    if (!linked.has(path.resolve(folder, e.name))) {
      ctx.fail("overview", ov, `does not link ${e.name}`);
    }
  }
}

function checkBacklink(file, ctx) {
  const head = readText(file).split("\n").slice(0, 15).join("\n");
  if (!BACKLINK_RE.test(head)) ctx.fail("backlink", file, "missing top backlink to 00-overview.md");
}

// ---------------------------------------------------- rule 5: reverse coverage
function checkReverseCoverage(allText, ctx) {
  const seen = new Set();
  const entries = [];
  for (const pattern of CONFIG.entryGlobs) {
    for (const pat of expandBraces(pattern)) {
      for (const key of globFiles(pat, ctx.root)) {
        if (!seen.has(key)) {
          seen.add(key);
          entries.push(key);
        }
      }
    }
  }
  entries.sort();
  for (const key of entries) {
    if (!allText.includes(key)) {
      ctx.fail("reverse-coverage", key, "entry point referenced by no doc");
    }
  }
}

/**
 * Finds all `[CONFIGURE BEFORE LISTING...]` placeholders in Markdown content.
 */
export function findStrictListingPlaceholders(text) {
  const content = String(text ?? "");
  const matches = [];
  for (const m of content.matchAll(STRICT_LISTING_RE)) {
    const line = content.slice(0, m.index).split("\n").length;
    matches.push({ placeholder: m[0], line });
  }
  return matches;
}

function checkStrictListing(ctx) {
  const targets = [
    path.join(ctx.root, "SECURITY.md"),
    ...walk(path.join(ctx.root, "marketplace"), ".md"),
  ].filter((filePath) => fs.existsSync(filePath));

  const findings = [];
  for (const filePath of targets) {
    for (const match of findStrictListingPlaceholders(readText(filePath))) {
      findings.push({ file: ctx.rel(filePath), ...match });
      ctx.fail(
        "strict-listing",
        filePath,
        `unconfigured marketplace placeholder -> ${match.placeholder}`,
        match.line,
      );
    }
  }
  return findings;
}

/**
 * Runs all documentation checks against `options.root` without mutating
 * module-global state, returning structured errors, warnings, and summary data.
 */
export function runDocsCheck(options = {}) {
  const root = path.resolve(options.root || process.env.DOCS_CHECK_ROOT || process.cwd());
  const strictListing = Boolean(
    options.strictListing ??
    (process.env.DOCS_CHECK_STRICT_LISTING === "1" || process.env.DOCS_CHECK_STRICT_LISTING === "true"),
  );
  const docsDir = path.join(root, CONFIG.docsRoot);
  const router = path.join(root, CONFIG.router);

  const errors = [];
  const warnings = [];
  const rel = (p) => {
    const r = path.isAbsolute(p) ? path.relative(root, p) : p;
    return (r || ".").split(path.sep).join("/");
  };

  if (!fs.existsSync(docsDir)) {
    const msg = `docs-check: ${CONFIG.docsRoot} does not exist`;
    return {
      exitCode: 1,
      errors: [msg],
      warnings,
      checked: 0,
      docFiles: [],
      extraDocFiles: [],
      folders: [],
      strictListingFindings: [],
      missingDocsDir: true,
    };
  }

  const ctx = {
    root,
    checked: 0,
    headingCache: new Map(),
    rel,
    fail: (rule, p, msg, line) =>
      errors.push(`${line ? `${rel(p)}:${line}` : rel(p)}: ${rule}: ${msg}`),
    warn: (rule, p, msg) => warnings.push(`${rel(p)}: ${rule}: ${msg}`),
  };

  const docFiles = walk(docsDir, ".md");
  const extraDocFiles = [
    ...CONFIG.extraDocs.map((f) => path.join(root, f)).filter((f) => fs.existsSync(f)),
    ...CONFIG.extraDocDirs.flatMap((d) => walk(path.join(root, d), ".md")),
  ];
  const checkedDocs = [...docFiles, ...extraDocFiles];
  const sources = [...checkedDocs, ...(fs.existsSync(router) ? [router] : [])];
  const texts = new Map();

  for (const f of sources) {
    const t = readText(f);
    texts.set(f, t);
    checkLinks(f, t, ctx);
  }
  for (const f of checkedDocs) checkPaths(f, texts.get(f), ctx);
  if (fs.existsSync(router)) checkPaths(router, texts.get(router), ctx);
  else ctx.warn("router", router, "router file missing");

  const folders = fs.readdirSync(docsDir, { withFileTypes: true })
    .filter((e) => e.isDirectory() && /^\d{2,}-/.test(e.name) && !CONFIG.skipDirs.has(e.name))
    .map((e) => path.join(docsDir, e.name))
    .sort();

  for (const folder of folders) {
    checkFolder(folder, ctx);
    for (const f of walk(folder, ".md")) {
      if (path.basename(f) !== CONFIG.overview) checkBacklink(f, ctx);
    }
  }

  checkReverseCoverage([...texts.values()].join("\n"), ctx);

  const strictListingFindings = strictListing ? checkStrictListing(ctx) : [];

  return {
    exitCode: errors.length ? 1 : 0,
    errors,
    warnings,
    checked: ctx.checked,
    docFiles,
    extraDocFiles,
    folders,
    strictListingFindings,
    missingDocsDir: false,
  };
}

/**
 * Parses CLI flags and environment overrides for `docs-check.mjs`.
 */
export function parseCliArgs(argv = process.argv.slice(2), env = process.env) {
  let root = env.DOCS_CHECK_ROOT || process.cwd();
  let strictListing = env.DOCS_CHECK_STRICT_LISTING === "1" || env.DOCS_CHECK_STRICT_LISTING === "true";
  let help = false;
  let positionalRootSet = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--strict-listing") {
      strictListing = true;
    } else if (arg === "--help" || arg === "-h") {
      help = true;
    } else if (arg === "--root") {
      const next = argv[i + 1];
      if (!next || next.startsWith("-")) {
        throw new Error("Missing value for --root");
      }
      root = next;
      i++;
    } else if (arg.startsWith("--root=")) {
      const val = arg.slice("--root=".length);
      if (!val) throw new Error("Missing value for --root=");
      root = val;
    } else if (arg.startsWith("-")) {
      throw new Error(`Unknown option: ${arg}`);
    } else if (!positionalRootSet) {
      root = arg;
      positionalRootSet = true;
    } else {
      throw new Error(`Unexpected positional argument: ${arg}`);
    }
  }

  return { root: path.resolve(root), strictListing, help };
}

/**
 * CLI entrypoint executing documentation checks and printing diagnostics.
 */
export function main(argv = process.argv.slice(2), env = process.env) {
  let parsed;
  try {
    parsed = parseCliArgs(argv, env);
  } catch (err) {
    console.error(`docs-check: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }

  if (parsed.help) {
    console.log(
      "Usage: node scripts/docs-check.mjs [root] [--root <dir>] [--strict-listing] [--help]\n" +
      "Env:   DOCS_CHECK_ROOT=<dir>  DOCS_CHECK_STRICT_LISTING=1",
    );
    return 0;
  }

  const result = runDocsCheck({ root: parsed.root, strictListing: parsed.strictListing });
  if (result.missingDocsDir) {
    console.error(result.errors[0]);
    return 1;
  }

  for (const w of result.warnings) console.error(`warning: ${w}`);
  for (const e of result.errors) console.error(`error: ${e}`);
  console.log(
    `docs-check: ${result.docFiles.length + result.extraDocFiles.length} doc files ` +
    `(${result.docFiles.length} in docs/, ${result.extraDocFiles.length} top-level/marketplace), ` +
    `${result.folders.length} subjects, ${result.errors.length} errors, ${result.warnings.length} warnings`,
  );
  return result.exitCode;
}

function isEntrypoint() {
  if (!process.argv[1]) return false;
  try {
    return fs.realpathSync(fileURLToPath(import.meta.url)) === fs.realpathSync(process.argv[1]);
  } catch {
    return import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
  }
}

if (isEntrypoint()) {
  process.exit(main());
}
