#!/usr/bin/env node
// node-brotli-check.mjs: is this Node.js fixed for CVE-2026-111497 (Brotli
// decoder out-of-bounds write), and where does a project decode Brotli data?
//   node node-brotli-check.mjs [project-path]
// Run it with the SAME node binary that runs your app (check `which node`,
// your Dockerfile, or your platform's runtime setting).
// Exit code: 0 = fixed, 1 = action needed.
import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";

const FIXED = { 22: "22.23.4", 24: "24.22.1", 26: "26.12.1" };

const parts = (v) => v.replace(/^v/, "").split(".").map(Number);
export function atLeast(version, minimum) {
  const a = parts(version);
  const b = parts(minimum);
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] > b[i];
  return true;
}

/**
 * The fix added a new decoder error code (-17) and Node.js exposes it as
 * zlib.constants.BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH. Its presence is the
 * most direct sign that the patched decoder is built in; the version number
 * is the second signal.
 */
export function assessRuntime({ version, hasFixConstant, sharedBrotli }) {
  const major = parts(version)[0];
  const fixed = FIXED[major];
  const versionOk = fixed ? atLeast(version, fixed) : false;

  if (hasFixConstant) {
    return {
      status: "fixed",
      reason: versionOk || !fixed
        ? `Node.js ${version} has the patched Brotli decoder.`
        : `Node.js ${version} is below ${fixed} but has the patched decoder (a vendor backport).`,
    };
  }
  if (sharedBrotli) {
    return {
      status: "check",
      reason: `This Node.js uses the system Brotli library. Update the OS brotli package (it must include google/brotli commit 0ed4268), then Node.js itself.`,
    };
  }
  if (!fixed) {
    return {
      status: "vulnerable",
      reason: `Node.js ${major}.x is end of life and gets no fix. Move to 24.22.1 or 26.12.1 (or 22.23.4).`,
    };
  }
  return {
    status: "vulnerable",
    reason: versionOk
      ? `Node.js ${version} reports a fixed version but lacks the fix marker: rebuild or reinstall from nodejs.org.`
      : `Node.js ${version} is below the fixed release ${fixed}.`,
  };
}

// --- project scan: where Brotli from outside gets decoded -------------------
function readJson(file) {
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch {
    return null;
  }
}

function installedVersion(root, name) {
  return readJson(path.join(root, "node_modules", name, "package.json"))?.version ?? null;
}

const SOURCE_EXT = /\.(m?[jt]sx?|cjs)$/;

export function scanProject(root) {
  const findings = [];
  const express = installedVersion(root, "express");
  const bodyParser =
    readJson(path.join(root, "node_modules", "express", "node_modules", "body-parser", "package.json"))?.version ??
    installedVersion(root, "body-parser");
  if (bodyParser && parts(bodyParser)[0] >= 2) {
    findings.push(`body-parser ${bodyParser}${express ? ` (express ${express})` : ""}: express.json()/urlencoded() decode Brotli request bodies from any client.`);
  }
  const axios = installedVersion(root, "axios");
  if (axios) findings.push(`axios ${axios}: asks servers for Brotli and decodes responses.`);

  let usesFetch = false;
  let usesZlibBrotli = false;
  const walk = (dir) => {
    for (const entry of existsSync(dir) ? readdirSync(dir, { withFileTypes: true }) : []) {
      if (entry.name === "node_modules" || entry.name.startsWith(".") || entry.name === "dist" || entry.name === "build") continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (SOURCE_EXT.test(entry.name)) {
        const text = readFileSync(full, "utf8");
        if (/\bfetch\s*\(/.test(text)) usesFetch = true;
        if (/createBrotliDecompress|brotliDecompress/.test(text)) usesZlibBrotli = true;
      }
    }
  };
  walk(root);
  if (usesFetch) findings.push("fetch(): decodes Brotli responses even without asking for them.");
  if (usesZlibBrotli) findings.push("zlib Brotli decompression called directly in your code.");
  return findings;
}

// --- CLI -----------------------------------------------------------------------
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const runtime = {
    version: process.version,
    hasFixConstant: zlib.constants.BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH !== undefined,
    sharedBrotli: Boolean(process.config?.variables?.node_shared_brotli),
  };
  const result = assessRuntime(runtime);
  console.log("Node.js Brotli check (CVE-2026-111497)");
  console.log(`node:        ${runtime.version} (bundled brotli ${process.versions.brotli}; this number does not change with the fix)`);
  console.log(`fix marker:  ${runtime.hasFixConstant ? "present" : "missing"}`);
  console.log(`status:      ${result.status.toUpperCase()}`);
  console.log(`why:         ${result.reason}`);

  const root = process.argv[2] ? path.resolve(process.argv[2]) : null;
  if (root) {
    const findings = scanProject(root);
    console.log("");
    console.log(`Where ${path.basename(root)} decodes Brotli from outside:`);
    for (const f of findings.length ? findings : ["nothing found (the runtime should still be updated)"]) console.log(`  - ${f}`);
  }
  process.exit(result.status === "fixed" ? 0 : 1);
}
