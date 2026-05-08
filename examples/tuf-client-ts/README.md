# TUF client example (TypeScript)

Minimal example that downloads a TUF target using the published [`tuf-js`](https://www.npmjs.com/package/tuf-js) client. Behavior matches the Go example in `examples/tuf-client/go`: trust-on-first-use bootstrap, local cache under `tmp/`, and `prefixTargetsWithHash: false` for faynoSync-style target URLs.

## Requirements

- Node.js **^20.17.0** or **>=22.9.0** (see `tuf-js` engine field)

## Run

```bash
cd examples/tuf-client-ts
npm install
npm run start
```

## What it does

1. Creates `./tmp` (metadata) and `./tmp/download` (targets).
2. If `./tmp/root.json` is missing, downloads `1.root.json` from the metadata base URL and saves it as `root.json`.
3. Refreshes TUF metadata and downloads the configured target if it is not already cached.

## Configuration

Edit `client.ts`: set `baseURL`, `metadataBaseUrl` (derived from `baseURL`), and `target` to match your repository and artifact path.

## Note

This example uses **trust-on-first-use** for the initial root. For production, ship a known-good `root.json` out-of-band instead of downloading `1.root.json` over the network without prior trust.
