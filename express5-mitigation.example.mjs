// Stop-gaps for Express 5 apps until the Node.js update is deployed:
// both keep Brotli request bodies away from the decoder.
import zlib from "node:zlib";
import { createRequire } from "node:module";
const express = createRequire(import.meta.url)("express");

const br = zlib.brotliCompressSync(Buffer.from(JSON.stringify({ hello: "brotli" })));
const plain = JSON.stringify({ hello: "plain" });

// Option A: body-parser's own switch. Rejects every compressed body (gzip too).
function optionA() {
  const app = express();
  app.use(express.json({ inflate: false }));
  return app;
}

// Option B: refuse only Brotli, keep gzip and deflate working.
function rejectBrotliBodies(req, res, next) {
  const encoding = String(req.headers["content-encoding"] ?? "").toLowerCase();
  if (encoding.split(",").some((e) => e.trim() === "br")) {
    return res.status(415).json({ error: "Brotli request bodies are not accepted" });
  }
  next();
}
function optionB() {
  const app = express();
  app.use(rejectBrotliBodies);
  app.use(express.json());
  return app;
}

async function probe(name, app) {
  app.post("/", (req, res) => res.json({ got: req.body?.hello ?? null }));
  app.use((err, _req, res, _next) => res.status(err.status ?? 500).json({ error: err.type ?? err.message }));
  const server = await new Promise((r) => {
    const s = app.listen(0, () => r(s));
  });
  const url = `http://127.0.0.1:${server.address().port}/`;
  const send = async (body, encoding) => {
    const headers = { "content-type": "application/json" };
    if (encoding) headers["content-encoding"] = encoding;
    const res = await fetch(url, { method: "POST", headers, body });
    return `${res.status} ${await res.text()}`;
  };
  console.log(`${name}`);
  console.log(`  plain JSON:  ${await send(plain)}`);
  console.log(`  brotli JSON: ${await send(br, "br")}`);
  console.log(`  gzip JSON:   ${await send(zlib.gzipSync(plain), "gzip")}`);
  server.close();
}

await probe("Option A: express.json({ inflate: false })", optionA());
await probe("Option B: rejectBrotliBodies before express.json()", optionB());
