# Data Plane Vision (v2)

This idea has been in the air for a long time; this document captures it in one place.

## Motivation

No matter how much we optimize the API, it will eventually hit resource limits and push us toward DB clustering, replication, and similar ops — which we want to avoid.

For v2, the goal is to move the hot path to **SDK-driven edge-first reads with S3-backed response cache**.

## Two modes (both supported)

| Mode | Endpoint | Notes |
|------|----------|--------|
| **Dynamic API** | `/checkVersion` | Unchanged; existing clients and tooling keep working. |
| **Edge + S3 cache** | SDK `EdgeURL` → S3 manifests | New high-scale path for client version checks. |

## Edge + S3 mode — overview

### Configuration

- Toggle per app via API (`cdn` parameter on the application).
- Public S3 bucket for response manifests (metadata only; binaries stay on the existing artifact flow).
- Independent from `PERFORMANCE_MODE` (no coupling).
- SDK can optionally use edge-first behavior by passing `EdgeURL` in client config.

### Request flow

```
SDK Client (`BaseURL` + optional `EdgeURL`)
  ↓
If `EdgeURL` is set, SDK checks edge/S3 first
  ↓
  ├─ HIT  → return cached response to client
  └─ MISS → call Origin API (`/checkVersion`) via `BaseURL`
              ↓
            API returns normal response
              ↓
            SDK persists response to S3 cache path
              ↓
            Future checks → edge/S3 HIT
```

**Scale property:** origin API load is amortized per **cache key** (query dimensions), not per client.

Example: 100,000 clients on 5 distinct client versions → at most **5** origin calls per dimension set after warm-up, not 100,000.

In practice, cache keys multiply:

```
N ≈ client_versions × channel × platform × arch × updater × package
```

Example: 5 versions × 5 dimension combinations ≈ **25** origin calls to build cache coverage instead of 100,000 direct API checks.

### Publish / unpublish behavior

On publish or unpublish of any version:

1. Delete response manifests for the affected app scope.
2. Subsequent checks become MISS and repopulate cache through the normal SDK fallback path.

### Fallback fill (normal operation)

If edge/S3 returns MISS, SDK calls `/checkVersion` and then stores the received response in S3.

This naturally handles rare or new dimension combinations without pre-warm jobs.

### HTTP status behavior on edge/S3

The edge path typically returns `200 OK` when manifest object exists. MISS falls back to origin API.

| Updater / case | Approach |
|----------------|----------|
| Default JSON | Store full faynoSync response body in S3. |
| No update | Return API result, cache it under the same key rules. |
| Updater-specific artifact contracts | Keep existing contract; only response lookup path changes. |

Response caching behavior in this mode is separate from Redis caching used by `PERFORMANCE_MODE`.

For JavaScript SDK integrations (`electron-builder`, `tauri`, `squirrel`), updater-specific protocol details are handled in `js-sdk`.
API already returns and caches all required response payloads; SDK maps those payloads to updater-compatible HTTP semantics.

Example cached response payloads interpreted by `js-sdk`:

```json
{
  "status": "no_content"
}
```

SDK behavior: return `204 No Content` to the updater.

```json
{
  "status": "redirect",
  "url": "http://cb-faynosync-s3-public.web.garage.localhost:3902/electron-builder/electron-admin/0.0.0.2/nightly/darwin/arm64/latest.yml"
}
```

SDK behavior: return updater-facing redirect/link response based on the provided `url`.

### Manifest content and paths

Manifests store the **full faynoSync JSON response** (same fields as Dynamic API), for example:

```json
{
  "update_available": true,
  "update_url_deb": "https://<bucket>.s3.amazonaws.com/secondapp/stable/linux/amd64/secondapp-0.0.2.deb",
  "update_url_rpm": "https://<bucket>.s3.amazonaws.com/secondapp/stable/linux/amd64/secondapp-0.0.2.rpm",
  "changelog": "### Changelog\n\n- Added feature X\n- Fixed bug Y",
  "critical": true,
  "is_intermediate_required": true
}
```

**Path layout:**

```
/responses/{owner}/{app_name}/{channel}/{platform}/{arch}/{client_version}.json
```

**No `latest.json` on CDN:** version comparison stays server-side (or in precomputed per–client-version manifests). A single `latest.json` would push comparison logic to clients and break the original faynoSync model.

### Event → action (manifest lifecycle)

| Event | S3 / Edge action |
|-------|-------------------|
| Publish / unpublish | Delete manifest prefix for app scope |
| Any later check for missing key | SDK fallback to `/checkVersion` → write S3 → subsequent HITs |

Fields such as `critical`, `is_intermediate_required`, and `possible_rollback` are included when manifests are regenerated from `/checkVersion` logic.

## Implementation via SDK

SDK supports edge-first checks when `EdgeURL` is provided:

```go
client := faynosync.NewClient(faynosync.Config{
    BaseURL: "http://localhost:9000",
    EdgeURL: "http://faynosync-cdn-edge.web.garage.localhost:3902",
})
```

If `EdgeURL` is not provided, SDK behaves as before and calls API directly via `BaseURL`.

When app-level CDN mode is enabled, cached responses are stored at:

```
/responses/{owner}/{app_name}/{channel}/{platform}/{arch}/{client_version}.json
```

Each cached response object is stored with standard S3 cache headers:

```
Cache-Control: public, max-age=60, must-revalidate
```

**Outcome:** frequent version checks are served from edge/S3 cache, while API remains the source of truth and fallback on cache MISS.

## Goals

1. **SDK-first integration** — no separate CDN application required.
2. **Per-app control** — enable cache mode via app `cdn` parameter.
3. **Stable cache keying** — deterministic response path per client dimensions.
4. **Lifecycle safety** — publish/unpublish clears cached manifests for the app scope.
5. **Hot-path offload** — edge/S3 serves repeated checks, API handles MISS and control plane.

---

## Telemetry

Today, metrics are collected inside `/checkVersion` when `X-Device-ID` is present. With edge/S3 mode, version checks no longer always hit the API, so telemetry moves to a dedicated path. Beacon requests go through the edge path to API.

### Flow change

**Before:**

```
Client → (if X-Device-ID) telemetry inline → /checkVersion
```

**After:**

```
Client → CDN → (if X-Device-ID) → /telemetry/beacon
```

### `/telemetry/beacon`

`/checkVersion` still does light DB validation even in performance mode. The beacon endpoint should avoid per-request DB lookups.

Keep a small **in-memory allow-list index** — not a copy of the `apps_meta` collection. On reload, read only name fields from Mongo (projection / aggregation) and build nested sets, for example:

```
owner → app → { channels, platforms, architectures, versions }
```

**Loaded dimensions (names only):**

- owners
- applications
- channels
- platforms
- architectures
- versions

No full documents, changelog, artifacts, or other `apps_meta` payload in memory.

**Beacon validation:** reject requests where `(owner, app, channel, platform, arch)` is not in the index. Do **not** require `version` to match the allow-list — clients may still report a version that was deleted in the admin UI.

Team users are out of scope for this public beacon path.

### Rebuild on change

When `apps_meta` changes (app created, channel added, platform removed, version published, etc.):

1. Update DB
2. Rebuild allow-list index from name fields only
3. Atomically swap in-memory pointer

```go
var allowList atomic.Pointer[TelemetryAllowList]

func ReloadAllowList() {
    next := BuildAllowListFromDB() // projection: names only
    allowList.Store(next)
}

// In handlers:
idx := allowList.Load()
```

**Future (multi-instance):** optional periodic reload (e.g. every 30–60s) on all instances. Not required for single-node deployments.

### Example handler

```go
func HandleTelemetry(w http.ResponseWriter, r *http.Request) {
    idx := allowList.Load()

    owner := r.URL.Query().Get("owner")
    app := r.URL.Query().Get("app")
    channel := r.URL.Query().Get("channel")
    platform := r.URL.Query().Get("platform")
    arch := r.URL.Query().Get("arch")
    // version: recorded for stats; not required to be in allow-list

    if !idx.Valid(owner, app, channel, platform, arch) {
        w.WriteHeader(204)
        return
    }

    // increment counters (Redis, same as today)
}
```

This reduces DB load and speeds up the API while keeping statistics accurate for real client traffic.
