// node --test node-brotli-check.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { assessRuntime, atLeast, scanProject } from "./node-brotli-check.mjs";

const status = (version, hasFixConstant, sharedBrotli = false) =>
  assessRuntime({ version, hasFixConstant, sharedBrotli }).status;

test("version comparison", () => {
  assert.ok(atLeast("v24.22.1", "24.22.1"));
  assert.ok(atLeast("v24.23.0", "24.22.1"));
  assert.ok(!atLeast("v24.22.0", "24.22.1"));
  assert.ok(!atLeast("v22.9.0", "22.23.4"));
});

test("runtime status from version and fix marker", () => {
  assert.equal(status("v26.12.1", true), "fixed");
  assert.equal(status("v24.22.1", true), "fixed");
  assert.equal(status("v22.23.4", true), "fixed");
  assert.equal(status("v26.12.0", false), "vulnerable");
  assert.equal(status("v24.22.0", false), "vulnerable");
  assert.equal(status("v20.20.2", false), "vulnerable"); // end of life
  assert.equal(status("v25.9.0", false), "vulnerable"); // end of life
  assert.equal(status("v22.22.0", true), "fixed"); // vendor backport
  assert.equal(status("v24.22.1", false), "vulnerable"); // odd build: version says fixed, marker missing
  assert.equal(status("v24.22.0", false, true), "check"); // links system brotli
});

test("project scan finds the Brotli entry points", () => {
  const root = mkdtempSync(path.join(tmpdir(), "brcheck-"));
  const write = (file, content) => {
    mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    writeFileSync(path.join(root, file), typeof content === "string" ? content : JSON.stringify(content));
  };
  write("node_modules/express/package.json", { name: "express", version: "5.3.0" });
  write("node_modules/express/node_modules/body-parser/package.json", { name: "body-parser", version: "2.4.0" });
  write("node_modules/axios/package.json", { name: "axios", version: "1.20.0" });
  write("src/hooks.ts", "const r = await fetch(url);");
  write("src/unpack.js", "zlib.createBrotliDecompress()");
  const findings = scanProject(root);
  assert.equal(findings.length, 4);
  assert.match(findings[0], /body-parser 2\.4\.0 \(express 5\.3\.0\)/);
  rmSync(root, { recursive: true });
});

test("Express 4 (body-parser 1) is not flagged for request bodies", () => {
  const root = mkdtempSync(path.join(tmpdir(), "brcheck-"));
  mkdirSync(path.join(root, "node_modules/body-parser"), { recursive: true });
  writeFileSync(path.join(root, "node_modules/body-parser/package.json"), JSON.stringify({ name: "body-parser", version: "1.20.9" }));
  assert.deepEqual(scanProject(root), []);
  rmSync(root, { recursive: true });
});
