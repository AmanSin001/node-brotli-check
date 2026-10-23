# node-brotli-check

Check whether a Node.js runtime is fixed for **CVE-2026-111497**, the Brotli decoder out-of-bounds write fixed on October 21, 2026 (Node.js 26.12.1, 24.22.1 and 22.23.4), and find where a project decodes Brotli data from outside. No dependencies.

Full write-up: [Node.js Brotli decoder vulnerability (CVE-2026-111497)](https://www.codewares.in/blog/node-js-brotli-vulnerability-cve-2026-111497)

## How it knows

The fix added a new Brotli decoder error code, which Node.js exposes as `zlib.constants.BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` (`-17`). Patched builds have it; unpatched builds do not. The bundled Brotli version string (`process.versions.brotli`, 1.2.0) is the same before and after the fix, so it cannot tell you.

One-liner:

```bash
node -p "require('zlib').constants.BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH"
# -17 = patched, undefined = not patched
```

## Usage

Run it with the **same `node` binary that runs your app** (your Dockerfile, service file or platform setting):

```bash
curl -O https://raw.githubusercontent.com/AmanSin001/node-brotli-check/main/node-brotli-check.mjs
node node-brotli-check.mjs            # runtime only
node node-brotli-check.mjs ./my-api   # runtime + project scan
echo $?                               # 0 = fixed, 1 = action needed
```

## Results on official Node.js builds

```
node-v20.20.2  fix marker: missing  VULNERABLE  (end of life, no fix)
node-v24.22.0  fix marker: missing  VULNERABLE  (below 24.22.1)
node-v24.22.1  fix marker: present  FIXED
node-v26.12.0  fix marker: missing  VULNERABLE  (below 26.12.1)
node-v26.12.1  fix marker: present  FIXED
```

Project scan on an Express 5 API:

```
Where my-api decodes Brotli from outside:
  - body-parser 2.4.0 (express 5.3.0): express.json()/urlencoded() decode Brotli request bodies from any client.
  - axios 1.20.0: asks servers for Brotli and decodes responses.
  - fetch(): decodes Brotli responses even without asking for them.
```

## What decodes outside Brotli (tested with a harmless payload)

| Code path | Decodes Brotli? |
|---|---|
| Express 5 `express.json()` / `urlencoded()` request bodies | Yes |
| `fetch()` responses | Yes, even if the request did not offer `br` |
| axios responses | Yes |
| Express 4 request bodies | No (415) |
| `http.get()` | No |
| Next.js route handlers | No (raw bytes) |

## Stop-gap for Express 5

Until the Node.js update is deployed, keep Brotli request bodies away from the decoder. See [`express5-mitigation.example.mjs`](express5-mitigation.example.mjs) (needs `npm install express@5` to run): either `express.json({ inflate: false })`, or a small middleware that rejects `Content-Encoding: br`. Neither helps with `fetch()` or axios responses, and neither replaces the update.

## Tests

```bash
node --test node-brotli-check.test.mjs
```

## Notes

- Some Linux distribution builds link the system Brotli library. The checker reports `CHECK` for those: update the OS Brotli package as well as Node.js.
- Node.js 20 and older are end of life and get no fix. Move to 24.22.1 or 26.12.1.

## License

MIT. Need your Node.js services updated? [CodeWares](https://www.codewares.in/gigs/fix-nextjs-react-node-python-bugs).
