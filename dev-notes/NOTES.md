# faynoSync Notes

## 1. Vision / Philosophy

faynoSync is inspired by systems like Omaha, but it has different goals.
It is not just an "updater"; it is a server-first update delivery platform.

Core principle:
keep the client simple, and move orchestration, policy, rollout control, and operational logic to the server.

What this means in practice:
- the server makes delivery decisions;
- the client remains minimal and predictable;
- integration stays composable, opt-in, and not tightly coupled to a specific SDK.

## 2. Non-goals

- Do not build an opinionated client runtime that dictates application architecture.
- Do not replicate full device management platforms.
- Do not expand client-side complexity without clear operational value for server-side control.

## 3. Current limitations

### 3.1 Ecosystem state

The ecosystem is still early:
- adoption is limited;
- integrations are still few;
- external contributors are limited;
- bus factor remains high.

### 3.2 Security maturity level

The current TUF implementation should not be considered independently audited or formally verified for high-security production environments.
Required next steps: external audit, scenario-based analysis, and deeper testing for rollback/freeze risk classes.

## 4. Ecosystem priorities

Near-term investments with the highest impact:

1. SDKs:
- Go
- Rust
- Node.js
- Python

2. CI/CD integrations:
- GitHub Actions
- GitLab CI
- Jenkins

3. Infrastructure integrations:
- Kubernetes
- Helm

## 5. Rollout architecture ideas

### 5.1 Base rollout model

Rollout should be staged and controlled:
1% -> 5% -> 20% -> 50% -> 100%,
with explicit progression conditions between stages.

### 5.2 Mature rollout system properties

Not just "send update to 10% of users", but ensure:
- deterministic bucketing;
- sticky assignment;
- platform-aware rollout;
- failure-rate monitoring;
- automatic pause;
- automatic rollback threshold (for example, pause when crash_rate > 3%).

### 5.3 Cohorts and targeting

This direction is currently considered questionable and requires separate design with a privacy-first focus.
Reason: some targeting attributes may require collecting or processing sensitive client data.

Current position:
- do not collect personal data without a clear operational need;
- do not tie rollout decisions to user-level identifiers;
- rely on the minimal set of technical attributes already present in update requests (channel, version, platform, arch).

What is acceptable without changing the privacy model:
- staged rollout by channel/platform/arch;
- deterministic bucketing on an anonymous technical installation identifier (without user identity), if explicitly approved.

Status: idea under review, not a priority for the next iteration.

### 5.4 Safe rollout control mechanisms

- throttling;
- kill switches;
- emergency rollback;
- canary populations (internal staff -> QA -> opt-in users -> beta cohort).

### 5.5 Channel management

The current model tightly couples `channel` to request URL and S3 key.
Idea: allow updating `channel` for a specific version after upload.

Technical impact:
- artifact migration in storage;
- re-signing TUF metadata;
- clear contract for how the client discovers its effective channel after a change.

For now, the value of this scenario is still uncertain.

## 6. Telemetry & policy future

### 6.1 Policy engine (server-side)

Goal: not a flat set of flags, but a controlled policy engine:
- disable updates;
- force updates;
- maintenance windows;
- pinned versions;
- admin approval;
- update deferrals.

### 6.2 Two-layer telemetry model

Layer 1: Operational realtime layer
- rollout health;
- crash spikes;
- failure rate;
- rollback triggers;
- rollout pause conditions.

Primary components:
- Redis;
- Prometheus metrics (optional);
- Grafana dashboards (optional).

Layer 2: Durable event history
- audit trail;
- raw events;
- forensic analysis;
- historical analytics.

Primary component:
- MongoDB.

Current baseline:
- During check-for-update, the server already has: channel, version, platform, arch.
- These signals are stored in Redis for initial near-realtime analysis.

### 6.3 Event flow

Client
  ->
Telemetry API
  ->
Redis (realtime counters/windows)
  ->
MongoDB (raw events)
  ->
Decision Engine
  ->
Actions:
  - pause rollout
  - rollback
  - throttle
  - alert

### 6.4 Decision Engine (draft logic)

Example rule:

IF:
- update_failed_rate > X
- version == 2.4.1
- platform == windows

THEN:
- pause rollout

Redis key examples for realtime counters:
- stats:update_failed:version:2.4.1
- stats:crash_after_update:windows

Raw event example in MongoDB:
{
  "event": "update_failed",
  "version": "2.4.1",
  "platform": "windows",
  "error_code": "ACCESS_DENIED",
  "timestamp": "..."
}

### 6.5 Metrics and UI planes

Prometheus metrics exposed by server:
- faynosync_update_failures_total
- faynosync_rollout_pause_triggered
- faynosync_client_outdated_total

Dashboard scope (control plane):
- Applications -> Releases -> Rollout health
- Failure rate
- Crash rate
- Adoption %
- Pause rollout
- Trigger rollback

Grafana scope (observability plane):
- deep metrics;
- advanced charts;
- infra observability;
- alerting.

Design principle:
- Dashboard = control plane
- Grafana = observability plane

## 7. Open questions

- What is the minimal policy DSL that delivers value without unnecessary complexity?
- Which telemetry signals are sufficient for automatic pause/rollback with low noise?
- Which channel model can be made more flexible without increasing client complexity?
- Where is the boundary between a "simple client" and necessary client-side diagnostics?
