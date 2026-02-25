# PR / Merge Summary (codex/osint-framework-hardening)

## Scope

This branch upgrades the project from a single-process prototype into a more production-ready OSINT platform with:

- persistent scan metadata and normalized correlation output
- case management (API + dashboard workspace)
- provider abstraction and Maigret-backed username workflows
- Redis-backed distributed queue with separate worker process
- worker leases / heartbeat / stale recovery
- Redis pub/sub event bridge for WebSocket updates
- dashboard UX upgrades (clickable graph nodes, discovered links panel, event telemetry panel)

## Major Architecture Changes

### 1. Data / Results
- `correlated_intel` is persisted and returned by API
- normalized intel model added (`entities`, `relations`, `evidence`)
- `modules_total` persisted for stable progress after restart

### 2. Case Management
- new DB entities for `cases`, `case_targets`, `case_notes`
- scans can be attached to a `case_id`
- case CRUD/list/detail APIs and dashboard UI integration

### 3. Plugin / Provider Standardization
- provider result shape introduced (`ProviderResult`)
- external-data plugins refactored toward provider abstraction
- username module refactored into provider-chain (`Maigret` + HTTP fallback)

### 4. Distributed Execution
- Redis queue backend (`pending` / `processing`)
- separate worker runtime (`run_worker.py`)
- API process can run queue-only mode while workers execute scans

### 5. Reliability (Worker Leases)
- lease claim + heartbeat + lease clear
- stale `running` job recovery on worker startup
- recovered jobs can be re-enqueued idempotently

### 6. Real-time Events
- Redis pub/sub event bus for worker-generated WebSocket events
- API bridge subscribes and rebroadcasts to connected WebSocket clients
- event envelope metadata now forwarded to UI (`source`, `channel`, `sent_at_ms`, `bridge_instance`, delays)

## UI / UX Improvements

- dynamic target types and validation hints
- `person_name` target mode with dedicated modules
- clickable graph nodes for discovered links
- `Discovered Links` panel (deduped, multi-module extraction)
- `Case Workspace` panel (tracked targets, jobs, notes)
- `Event Bus Telemetry` panel with WS/Redis debug metadata
- premium visual redesign (new typography, layout polish, responsive improvements)

## Migrations / Schema

### SQLite compatibility
Runtime compatibility migrations remain in place for local/dev DBs.

### Alembic
Apply in order:

1. `20260224_0001_initial_schema.py`
2. `20260225_0002_case_management.py`
3. `20260225_0003_worker_leases.py`

## Runtime Modes

### Single-process (dev)
- `python run.py`

### Distributed (Redis)
1. Start Redis
2. API:
   - `OSINT_QUEUE_MODE=redis OSINT_REDIS_URL=redis://127.0.0.1:6379/0 python run.py`
3. Worker:
   - `OSINT_QUEUE_MODE=redis OSINT_REDIS_URL=redis://127.0.0.1:6379/0 python run_worker.py`

## Verification Checklist (Recommended Before Merge)

- `python -m unittest`
- `python -m py_compile $(find osint_framework -name '*.py')`
- `node --check osint_framework/web/static/js/app.js`
- `node --check osint_framework/web/static/js/ws.js`
- Smoke test:
  - `/api/v1/status`
  - `/api/v1/modules`
  - create case
  - start scan with `case_id`
  - verify WebSocket `queued -> running -> module_result -> completed`

## Merge Risks / Watch Items

- Existing local `osintdb.db` may contain older rows; keep SQLite compat migrations enabled for dev users.
- `maigret` runtime depends on environment health and may fallback to HTTP provider if CLI is unavailable.
- Redis/WebSocket telemetry assumes Redis pub/sub connectivity; UI should still function without metadata if disabled.
- Frontend cache (especially Safari) may require hard refresh after JS/CSS changes.

## Merge Strategy

Preferred:
- Open PR from `codex/osint-framework-hardening` into `main`
- Run CI (tests + smoke if available)
- Merge with a merge commit to preserve milestone history

If direct merge is required:
- pull latest `main`
- rebase or merge `main` into branch first
- rerun tests and Redis worker smoke
- merge only after migration order is validated
