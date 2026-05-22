# Data Plane Vision (v2)

This idea has been in the air for a long time; this document captures it in one place.

## Motivation

No matter how much we optimize the API, it will eventually hit resource limits and push us toward DB clustering, replication, and similar ops — which we want to avoid.

For v2, the goal is to build the update flow as **zero-downtime, CDN-native auto-update infrastructure**.

## Two modes (both supported)

| Mode | Endpoint | Notes |
|------|----------|--------|
| **Dynamic API** | `/checkVersion` | Unchanged; existing clients and tooling keep working. |
| **Static CDN** | CDN edge → S3 manifests | New path for high-scale client traffic. |

## Static CDN mode — overview

### Configuration

- Toggle per admin / per app via API.
- Env vars for CloudFront cache invalidation (AWS-specific for now).
- Public CDN S3 bucket for response manifests (metadata only; binaries stay on the existing private flow).
- Works alongside `PERFORMANCE_MODE=true` (Redis caches the same response shapes today).

### Request flow

```
Client
  ↓
CDN / Edge
  ↓
  ├─ HIT  → serve manifest from S3
  └─ MISS → Origin API (/checkVersion)
              ↓
            Persist manifest to S3
              ↓
            Future requests → CDN HIT (no API)
```

**Scale property:** work is amortized per **cache key** (query dimensions), not per client.

Example: 100,000 clients on 5 distinct client versions → at most **5** origin calls per dimension set after warm-up, not 100,000.

In practice, warm-up keys multiply:

```
N ≈ client_versions × channel × platform × arch × updater × package
```

Example: 5 versions × 5 dimension combinations ≈ **25** origin calls on publish — well within API capacity (~1000 req/s on a minimal server).

### Publish / unpublish (primary path)

On publish or unpublish of the version (any version):

1. Delete all response manifests for that app scope from the CDN S3 bucket.
2. Invalidate CDN cache for the affected paths.
3. **Warm manifests:** run `/checkVersion` logic for each known `(owner, app, channel, platform, arch, client_version, updater, package, …)` combination and write JSON to S3.

This is the main path; it avoids a thundering herd of client-driven MISS traffic right after a release.

### Lazy fill (fallback)

If CDN mode is enabled, the API may also persist a manifest at the end of `/checkVersion` when handling a MISS (origin fill).

Use this for rare or new dimension combinations that were not warmed on publish.

### HTTP status codes on CDN

The edge/CDN typically returns `200 OK` for objects that exist. Updater-specific behavior must be handled explicitly:

| Updater / case | Approach |
|----------------|----------|
| Default JSON | Store full faynoSync response body in S3. |
| No update (e.g. squirrel, electron-builder, tauri) | Omit the object and/or small logic in the CDN module (204 No Content). |
| electron-builder, squirrel_windows | Clients already expect CDN-hosted artifacts; place YML / RELEASES at the correct paths (no change to client contract). |

`PERFORMANCE_MODE` already caches `(body, http_status)` in Redis; CDN manifests should mirror the same semantics per updater type.

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

**Path layout (draft):**

```
/responses/{owner}/{app_name}/{channel}/{platform}/{arch}/{client_version}.json
```

Alternative: hash-based key, e.g. `sha256(owner + app + channel + platform + arch + client_version)`.

**No `latest.json` on CDN:** version comparison stays server-side (or in precomputed per–client-version manifests). A single `latest.json` would push comparison logic to clients and break the original faynoSync model.

### Event → action (manifest lifecycle)

| Event | S3 / CDN action |
|-------|------------------|
| Publish / unpublish latest | Delete manifest prefix for app scope → warm all known dimension keys → invalidate CDN |
| Rare new client dimension | Lazy fill on MISS → write S3 → subsequent HITs |

Fields such as `critical`, `is_intermediate_required`, and `possible_rollback` are included when manifests are regenerated from `/checkVersion` logic.

## Implementation: `faynosync-cdn-module`

A small TypeScript app (separate repo, e.g. `faynosync-cdn-module`):

- Built artifacts published on GitHub Releases.
- CDN-agnostic where possible; only cache invalidation is AWS/CloudFront initially.
- Avoid Lambdas and heavy edge functions; keep the module simple.

**API unavailable (edge stub):** if origin is down on MISS, return a standard body with `"update_available": false`. This is a safety stub only — operators still need the API up for publish and warm-up. Clients that already have S3/CDN HITs can keep updating while API is offline.

**Nice-to-have (deferred):** faynoSync self-deploys and updates the CDN module on the bucket — low priority for now.

**Outcome:** clients can receive update metadata even when the faynoSync API is down, as long as manifests and artifacts are already on CDN/S3.

## Goals

1. **Portable data plane** — minimal AWS coupling; generic CDN + S3; CloudFront invalidation only where needed today.
2. **Simple TS edge module** — always available via GitHub Releases.
3. **Separate repository** — `faynosync-cdn-module`.
4. **Lifetime-scale API** — hot path offloaded; control plane (publish, admin) stays on API.
5. **Resilience** — cached manifests serve clients when API is temporarily unavailable.

---

## Telemetry

Today, metrics are collected inside `/checkVersion` when `X-Device-ID` is present. With CDN mode, version checks no longer always hit the API, so telemetry moves to a dedicated path. The CDN module can forward beacon requests.

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
