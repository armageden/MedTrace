#!/usr/bin/env node

/**
 * Offline Atlassian Forge manifest + compiled handler export validator.
 *
 * Validates `manifest.yml` against `@forge/manifest` (`FULL`, `PRODUCT_TRIGGER`,
 * and `AGENT_PRODUCT_CONTEXT`), verifies compiled handlers in `dist/index.js`,
 * and enforces local-asset icons (no remote `https://` UI module icon URLs).
 */

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';

const require = createRequire(import.meta.url);
const { ProcessorBuilder, ValidationTypes } = require('@forge/manifest');

const REQUIRED_VALIDATIONS = [
  ['FULL', ValidationTypes.FULL],
  ['PRODUCT_TRIGGER', ValidationTypes.PRODUCT_TRIGGER],
  ['AGENT_PRODUCT_CONTEXT', ValidationTypes.AGENT_PRODUCT_CONTEXT],
];

const REMOTE_URL_RE = /^https?:\/\//i;
const RESOURCE_ICON_RE = /^resource:([^;]+);(.+)$/;

function formatManifestErrors(validationLabel, rawErrors) {
  if (!Array.isArray(rawErrors)) return { errors: [], warnings: [] };
  const errors = [];
  const warnings = [];
  for (const item of rawErrors) {
    const loc =
      typeof item?.line === 'number' && item.line > 0
        ? ` (line ${item.line}${typeof item.column === 'number' ? `:${item.column}` : ''})`
        : '';
    const msg = `[${validationLabel}]${loc} ${item?.message || String(item)}`;
    if (item?.level === 'warning') {
      warnings.push(msg);
    } else {
      errors.push(msg);
    }
  }
  return { errors, warnings };
}

function collectIconIssues(modules, resources, rootDir) {
  const errors = [];
  const resourceMap = new Map();
  if (Array.isArray(resources)) {
    for (const r of resources) {
      if (r && typeof r.key === 'string' && typeof r.path === 'string') {
        resourceMap.set(r.key, r.path);
      }
    }
  }

  function inspectValue(value, moduleType, entryKey, keyName, visited) {
    if (typeof value === 'string') {
      const trimmed = value.trim();
      if (REMOTE_URL_RE.test(trimmed)) {
        errors.push(
          `[icon-policy] Module "${moduleType}" (key="${entryKey}") field "${keyName}" uses remote icon URL "${trimmed}". Bundle a local asset via Forge resources instead.`
        );
        return;
      }
      const resMatch = RESOURCE_ICON_RE.exec(trimmed);
      if (resMatch) {
        const [, resKey, assetRelPath] = resMatch;
        const resPath = resourceMap.get(resKey);
        if (!resPath) {
          errors.push(
            `[icon-policy] Module "${moduleType}" (key="${entryKey}") references unknown resource "${resKey}" in "${trimmed}".`
          );
          return;
        }
        const resDir = path.resolve(rootDir, resPath);
        const assetFullPath = path.resolve(resDir, assetRelPath);
        if (assetFullPath !== resDir && !assetFullPath.startsWith(resDir + path.sep)) {
          errors.push(
            `[icon-policy] Module "${moduleType}" (key="${entryKey}") icon path escapes resource directory: "${trimmed}".`
          );
          return;
        }
        if (!fs.existsSync(assetFullPath) || fs.statSync(assetFullPath).isDirectory()) {
          errors.push(
            `[icon-policy] Module "${moduleType}" (key="${entryKey}") icon file does not exist: ${path.relative(rootDir, assetFullPath)}.`
          );
        }
      }
      return;
    }

    if (Array.isArray(value)) {
      for (const item of value) {
        inspectValue(item, moduleType, entryKey, keyName, visited);
      }
      return;
    }

    if (value && typeof value === 'object') {
      if (visited.has(value)) return;
      visited.add(value);
      for (const [k, v] of Object.entries(value)) {
        inspectValue(v, moduleType, entryKey, `${keyName}.${k}`, visited);
      }
    }
  }

  if (!modules || typeof modules !== 'object') {
    return errors;
  }

  for (const [moduleType, entries] of Object.entries(modules)) {
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      if (!entry || typeof entry !== 'object') continue;
      const entryKey = typeof entry.key === 'string' ? entry.key : '(unknown)';
      const visited = new WeakSet();
      for (const [prop, val] of Object.entries(entry)) {
        const lower = prop.toLowerCase();
        if (lower === 'icon' || lower === 'iconurl' || lower === 'icons') {
          inspectValue(val, moduleType, entryKey, prop, visited);
        } else if (val && typeof val === 'object') {
          // Walk nested objects (e.g. module icon objects) only looking for nested icon keys.
          const stack = [{ obj: val, path: prop }];
          while (stack.length > 0) {
            const { obj, path: objPath } = stack.pop();
            if (!obj || typeof obj !== 'object' || visited.has(obj)) continue;
            visited.add(obj);
            if (Array.isArray(obj)) {
              for (const item of obj) {
                if (item && typeof item === 'object') stack.push({ obj: item, path: objPath });
              }
              continue;
            }
            for (const [nestedKey, nestedVal] of Object.entries(obj)) {
              const nestedLower = nestedKey.toLowerCase();
              if (nestedLower === 'icon' || nestedLower === 'iconurl' || nestedLower === 'icons') {
                inspectValue(nestedVal, moduleType, entryKey, `${objPath}.${nestedKey}`, visited);
              } else if (nestedVal && typeof nestedVal === 'object') {
                stack.push({ obj: nestedVal, path: `${objPath}.${nestedKey}` });
              }
            }
          }
        }
      }
    }
  }

  return errors;
}

/**
 * Validates `manifest.yml`, verifies compiled handler exports in `dist/`,
 * and ensures no UI module uses a remote `http(s)://` icon URL.
 */
export async function validateManifest(options = {}) {
  const rootDir = path.resolve(options.rootDir || process.cwd());
  const manifestPath = path.resolve(rootDir, options.manifestFile || 'manifest.yml');
  const distDir = path.resolve(rootDir, 'dist');
  const distIndexPath = path.resolve(distDir, 'index.js');

  const errors = [];
  const warnings = [];
  const verifiedHandlers = [];

  if (!fs.existsSync(manifestPath)) {
    errors.push(`Manifest file not found: ${manifestPath}`);
    return { ok: false, errors, warnings, verifiedHandlers };
  }

  let typedContent;
  for (const [label, validationType] of REQUIRED_VALIDATIONS) {
    let result;
    try {
      result = await ProcessorBuilder.instance()
        .withValidation(validationType)
        .build()
        .process(manifestPath);
    } catch (err) {
      errors.push(`[${label}] Processor failed: ${err instanceof Error ? err.message : String(err)}`);
      continue;
    }

    const formatted = formatManifestErrors(label, result?.errors);
    warnings.push(...formatted.warnings);
    errors.push(...formatted.errors);

    if (!result?.success && formatted.errors.length === 0) {
      errors.push(`[${label}] Manifest validation failed without detailed errors.`);
    }
    if (!typedContent && result?.manifestObject?.typedContent) {
      typedContent = result.manifestObject.typedContent;
    }
  }

  if (!typedContent) {
    errors.push('Failed to parse manifest typedContent via @forge/manifest.');
    return { ok: false, errors, warnings, verifiedHandlers };
  }

  // Verify compiled backend bundle exists and exports every declared function handler.
  if (!fs.existsSync(distIndexPath)) {
    errors.push(
      `Compiled backend entry is missing at "${path.relative(rootDir, distIndexPath)}". Run "npm run build" before running manifest validation.`
    );
  } else {
    const functions = typedContent.modules?.function;
    if (!Array.isArray(functions) || functions.length === 0) {
      errors.push('manifest.yml modules.function must declare at least one function handler.');
    } else {
      const moduleCache = new Map();
      for (const fn of functions) {
        const fnKey = typeof fn?.key === 'string' ? fn.key : '(unknown)';
        const handler = typeof fn?.handler === 'string' ? fn.handler.trim() : '';
        const dotIdx = handler.lastIndexOf('.');
        if (!handler || dotIdx <= 0 || dotIdx === handler.length - 1) {
          errors.push(
            `[handler-export] Function "${fnKey}" has invalid handler "${handler}". Expected "<module>.<exportName>".`
          );
          continue;
        }

        const moduleRef = handler.slice(0, dotIdx);
        const exportName = handler.slice(dotIdx + 1);
        const targetModulePath = path.resolve(distDir, `${moduleRef}.js`);

        if (targetModulePath !== distDir && !targetModulePath.startsWith(distDir + path.sep)) {
          errors.push(
            `[handler-export] Function "${fnKey}" handler "${handler}" resolves outside dist/.`
          );
          continue;
        }

        if (!fs.existsSync(targetModulePath)) {
          errors.push(
            `[handler-export] Compiled module missing for function "${fnKey}" (${handler}): expected "${path.relative(rootDir, targetModulePath)}". Run "npm run build".`
          );
          continue;
        }

        let mod = moduleCache.get(targetModulePath);
        if (!mod) {
          try {
            mod = await import(pathToFileURL(targetModulePath).href);
            moduleCache.set(targetModulePath, mod);
          } catch (err) {
            errors.push(
              `[handler-export] Failed to dynamically import "${path.relative(rootDir, targetModulePath)}": ${err instanceof Error ? err.message : String(err)}`
            );
            continue;
          }
        }

        const resolvedExport = mod?.[exportName] ?? mod?.default?.[exportName];
        if (typeof resolvedExport !== 'function') {
          errors.push(
            `[handler-export] Function "${fnKey}" handler "${handler}" did not resolve to an exported function in "${path.relative(rootDir, targetModulePath)}" (got ${typeof resolvedExport}).`
          );
          continue;
        }

        verifiedHandlers.push({ key: fnKey, handler, file: path.relative(rootDir, targetModulePath) });
      }
    }
  }

  // Verify no https:// / http:// remote icon URLs remain in UI modules (and validate local resource icons).
  errors.push(...collectIconIssues(typedContent.modules, typedContent.resources, rootDir));

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    verifiedHandlers,
  };
}

const isMainModule =
  typeof process.argv[1] === 'string' &&
  process.argv[1].length > 0 &&
  (() => {
    try {
      const moduleRealUrl = (() => {
        try {
          return pathToFileURL(fs.realpathSync(fileURLToPath(import.meta.url))).href;
        } catch {
          return import.meta.url;
        }
      })();
      const resolvedArgv = pathToFileURL(path.resolve(process.argv[1])).href;
      const realArgv = fs.existsSync(process.argv[1])
        ? pathToFileURL(fs.realpathSync(process.argv[1])).href
        : resolvedArgv;
      return (
        import.meta.url === resolvedArgv ||
        import.meta.url === realArgv ||
        moduleRealUrl === realArgv
      );
    } catch {
      return false;
    }
  })();

if (isMainModule) {
  const rootArg = process.env.VALIDATE_MANIFEST_ROOT || process.cwd();
  const res = await validateManifest({ rootDir: rootArg });

  for (const w of res.warnings) {
    console.warn(`warning: ${w}`);
  }
  for (const e of res.errors) {
    console.error(`error: ${e}`);
  }

  if (!res.ok) {
    console.error(`validate-manifest: FAILED (${res.errors.length} error(s))`);
    process.exit(1);
  }

  console.log(
    `validate-manifest: OK (${REQUIRED_VALIDATIONS.map(([l]) => l).join(', ')}; ` +
      `${res.verifiedHandlers.length} handler exports verified; 0 remote icon URLs)`
  );
  process.exit(0);
}
