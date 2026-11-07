# OSINT Framework

A modular research prototype for **authorized** open-source investigations.
It combines a FastAPI dashboard/API, a plugin registry, persistent scan jobs,
optional Redis workers and WebSocket progress updates.

## Architecture and storage

`run.py` starts the API on **127.0.0.1:8000** by default. API routes live under
`/api/v1`; the live channel is `/ws`. Plugins perform target-specific work through
the pipeline and job manager. The default durable database is **SQLite through
async SQLAlchemy/aiosqlite**; the presence of `asyncpg` in dependencies does not
make PostgreSQL the default. Alembic migrations live in `alembic/`.

In Redis mode the API enqueues jobs; `run_worker.py` executes them separately.
Redis pub/sub events bridge worker progress back to API WebSocket clients.
In-process execution is also supported. Worker leases/heartbeats and recovery
settings are in `osint_framework/core/` and `job_queue/`.

## Setup

Use Python 3.12. Optional face-model packages are version/platform dependent.

```bash
python3.12 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
cp .env.example .env
python run.py
```

The root requirements file forwards to `osint_framework/requirements.txt`.
Review that pinned environment and its open dependency-update PRs before any
network deployment. The audit found known advisories in the installed HTTP,
multipart, token and transitive dependency stack; this PR does not assert that
those updates have been integrated or that the environment is production-safe.

Configuration is primarily `osint_framework/config.yaml` plus supported environment
overrides in `core/config.py`. Copying `.env.example` is not proof that every
library automatically reads it. `config.yaml` contains a wildcard host setting,
whereas the root launcher binds to loopback; be explicit when choosing another
entry point. Keep auth-disabled development local.

## API and CLI

Read-only local inspection after starting your own instance:

```bash
curl http://127.0.0.1:8000/api/v1/status
curl http://127.0.0.1:8000/api/v1/modules
python -m osint_framework.osint --help
```

A scan sends requests to external services and must be authorized for its target:

```bash
python -m osint_framework.osint scan domain example.com
# Equivalent API shape: POST /api/v1/scan
# {"target":"example.com","target_type":"domain"}
```

For separate workers, provide your own local Redis and use the same configuration
for both terminals:

```bash
OSINT_QUEUE_MODE=redis OSINT_REDIS_URL=redis://127.0.0.1:6379/0 python run.py
OSINT_QUEUE_MODE=redis OSINT_REDIS_URL=redis://127.0.0.1:6379/0 python run_worker.py
```

Optional providers require their own credentials, such as `SHODAN_API_KEY`,
`HIBP_API_KEY` or `NUMVERIFY_API_KEY`. Ollama summaries are optional. Provider
failures and fallback descriptors are not evidence that an identity was verified.

## Tests and development status

```bash
python -m pip install pytest pytest-socket
python -m pytest tests -q --disable-socket --allow-unix-socket
```

The audit ran 39 existing regressions successfully with external sockets blocked.
Pytest isolates each case in a temporary SQLite database. A first Linux CI run
exposed a shared-file database lock between API lifespans; the test fixture avoids
reusing persisted jobs/locks between independent cases.
This covers mocks/local persistence, not live providers, distributed recovery
under production load or calibrated biometric accuracy. The workflow uses the
same network-restricted tests. No passing badge is asserted.

`plugins/` contains domain/IP/email/person/username/phone and experimental image
pipelines; `web/` serves the dashboard and `cli/` contains Typer commands. The
vision pipeline may store crops, embeddings and a similarity index. Human review
and consent are required; a match score is not an identity determination.

## Security and privacy

Enable authentication and protect read endpoints before any controlled network
deployment; replace all example keys. Secure Redis and the database separately.
Face crops, case notes, reports, logs and indexes can contain personal information.
Keep them outside Git and apply appropriate access/retention rules. Use only
targets, images and datasets you are permitted to process. This is a research
prototype, not an assurance of anonymity or production security.


## License and contact

No license file is currently included; no new license or redistribution grant is asserted here. Author: [Muhammet Fatih Çetintaş](https://github.com/M-Fatih-C).
