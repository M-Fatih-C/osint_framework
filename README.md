# OSINT Framework

FastAPI tabanlı, plugin mimarili, gerçek zamanlı dashboard içeren modüler OSINT aracı.

## Özellikler

- `FastAPI` REST API + `WebSocket` canlı durum iletimi
- Plugin registry ile hedef tipine göre modül seçimi
- Asenkron worker pool ile paralel modül çalıştırma
- Redis tabanlı gerçek queue + ayrı worker process (opsiyonel dağıtık çalışma)
- Redis pub/sub ile worker -> API WebSocket event köprüsü (queue progress canlı aktarım)
- SQLite (SQLAlchemy async) ile job/result kalıcılığı
- API key auth (opsiyonel) + in-memory rate limiting + DB audit log
- Korelasyon çıktısı + opsiyonel Ollama tabanlı AI özet
- Web dashboard + CLI istemcisi
- Alembic migration altyapısı

## Mevcut Modüller

- `domain`: `DNS_Enum`, `Subdomain_Scanner`, `SSL_Info`, `WHOIS_Lookup`
- `ip`: `GeoIP`, `ASN_Lookup`, `Shodan_Scanner` (opsiyonel `SHODAN_API_KEY`)
- `email`: `Email_Verify`, `HIBP_Breach` (opsiyonel `HIBP_API_KEY`)
- `person_name`: `Person_Name_Analyzer`, `Person_Name_Handle_Generator`, `Person_Name_Search_Dorks`
- `username`: `Username_Checker` (Maigret tabanlı, otomatik fallback ile)
- `phone`: `Phone_Lookup` (lokal analiz + opsiyonel `NUMVERIFY_API_KEY`)

Not: UI yalnızca backend’de yüklü modüllerin desteklediği target tiplerini gösterir.

## Proje Yapısı

```text
.
├── Makefile                       # setup/smoke/cleanup kısa komutları
├── run.py                         # Repo kökünden API başlatma
├── run_worker.py                  # Redis queue worker process başlatma
├── alembic.ini                    # Alembic config
├── alembic/                       # Migration dosyaları
├── requirements.txt               # osint_framework/requirements.txt yönlendirmesi
├── osint_framework/
│   ├── api/                       # FastAPI app, routes, websocket manager
│   ├── core/                      # config, db, engine, logger, models
│   ├── job_queue/                 # worker pool + job manager
│   ├── plugins/                   # OSINT modülleri + registry
│   ├── reports/                   # AI summary + rapor yardımcıları
│   ├── web/                       # dashboard html/css/js
│   ├── cli/                       # Typer tabanlı CLI
│   ├── config.yaml                # Uygulama ayarları
│   └── osint.py                   # CLI entrypoint
├── scripts/                       # setup/smoke/runtime cleanup otomasyonları
└── tests/                         # Regression testleri
```

## Kurulum

```bash
python3 -m venv osint_framework/venv
source osint_framework/venv/bin/activate
pip install -r requirements.txt
```

Alternatif (otomasyon):

```bash
make setup
```

Bu komut:

- `.venv` oluşturur (yoksa)
- bağımlılıkları kurar
- test komutunu yazdırır

## Hızlı Operasyon Komutları

```bash
# bağımlılık kurulumu
make setup

# API smoke test (status/modules/case/scan)
make smoke

# runtime temizlik (log truncate + AppleDouble temizliği)
make clean-runtime

# runtime temizlik + __pycache__
make clean-runtime-all
```

## Çalıştırma

### API + Dashboard

Repo kökünden:

```bash
python run.py
```

Alternatif:

```bash
uvicorn osint_framework.api.main:app --host 127.0.0.1 --port 8000
```

Dashboard:

- `http://127.0.0.1:8000/`

### Redis Queue + Ayrı Worker Process (Önerilen Prod Benzeri Akış)

Bu modda API process yalnızca job oluşturur ve Redis queue'ya yazar. Taramaları ayrı `worker` process(leri) yürütür.

1. Redis başlat (`redis-server` veya Docker)
2. API'yi Redis queue modunda başlat
3. En az bir worker process başlat

Örnek (ortam değişkeni ile):

```bash
# 1) Redis (lokalde docker ile)
docker run --rm -p 6379:6379 redis:7-alpine

# 2) API (ayrı terminal)
OSINT_QUEUE_MODE=redis \
OSINT_REDIS_URL=redis://127.0.0.1:6379/0 \
python run.py

# 3) Worker (ayrı terminal)
OSINT_QUEUE_MODE=redis \
OSINT_REDIS_URL=redis://127.0.0.1:6379/0 \
python run_worker.py
```

Çoklu worker:

```bash
OSINT_QUEUE_MODE=redis OSINT_REDIS_URL=redis://127.0.0.1:6379/0 python run_worker.py
OSINT_QUEUE_MODE=redis OSINT_REDIS_URL=redis://127.0.0.1:6379/0 python run_worker.py
```

Notlar:

- `POST /scan` yanıtı bu modda genellikle `status="queued"` döner.
- Dashboard polling hala fallback olarak çalışır; Redis pub/sub bridge aktifse worker event'leri WebSocket üzerinden canlı iletilir.
- Redis queue modunda worker event'leri (`job_update`, `module_result`) Redis pub/sub üzerinden API process'e aktarılır ve WebSocket client'lara re-broadcast edilir.
- `GET /api/v1/status` içinde `queue_mode`, `queue_pending`, `queue_processing` alanları görünür.
- Worker process job çalıştırırken DB üzerinde lease/heartbeat tutar (`worker_lease_*` alanları).
- Worker startup sırasında `processing` listesindeki Redis işler pending'e taşınır ve lease'i geçmiş `running` job'lar otomatik toparlanır (`requeue` veya `error`).

### CLI

```bash
python -m osint_framework.osint --help
python -m osint_framework.osint scan domain example.com
```

## API Endpoint’leri

Base path: `/api/v1`

- `POST /scan` -> yeni tarama başlat
- `POST /auth/token` -> JWT access token al (JWT auth açıksa)
- `GET /auth/me` -> middleware auth context
- `GET /scan/{job_id}` -> tarama durumu/progress
- `GET /result/{job_id}` -> tam sonuç + korelasyon + AI özet
- `GET /modules` -> yüklü modül listesi
- `GET /status` -> framework iç durumu
- `GET /audit` -> son HTTP API audit kayıtları
- `POST /cases` -> case oluştur
- `GET /cases` -> case listesi
- `GET /cases/{case_id}` -> case detay (tracked targets, jobs, notes)
- `POST /cases/{case_id}/notes` -> case notu ekle
- `WS /ws` -> canlı durum bildirimleri

### Örnek istekler

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com","target_type":"domain"}'

curl -X POST http://127.0.0.1:8000/api/v1/cases \
  -H "Content-Type: application/json" \
  -d '{"title":"Client A - Phishing Investigation","tags":["client-a","phishing"]}'

curl -X POST http://127.0.0.1:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com","target_type":"domain","case_id":1}'

curl http://127.0.0.1:8000/api/v1/result/<job_id>
```

## Güvenlik (Opsiyonel)

`osint_framework/config.yaml` içinde:

- `security.enabled`: API key auth aç/kapat
- `security.api_keys`: kabul edilen anahtar listesi
- `security.protect_read_endpoints`: `GET` endpointleri de korunsun mu
- `api.rate_limit`: `100/minute`, `10/min`, `1000/hour` formatında limit
- `security.audit_logging`: tüm `/api/*` isteklerini DB’ye yaz
- `security.jwt.*`: JWT auth / token / RBAC ayarları
- `cache.type=redis` + `cache.url`: rate limit backend’i Redis’e taşır (fallback in-memory)
- `queue.*`: scan execution queue backend (`in_process` / `redis`)
- `logging.*`: dosya/console log davranışı + rotation parametreleri

## Username / Maigret Entegrasyonu

`Username_Checker` modülü artık öncelikli olarak `maigret` kullanır. `maigret` çalışmazsa veya
bulunamazsa modül otomatik olarak hafif HTTP fallback kontrolüne döner (GitHub/Twitter/Instagram/Reddit).

YAML ayarları (`osint_framework/config.yaml`):

- `integrations.maigret.enabled`: Maigret entegrasyonunu aç/kapat
- `integrations.maigret.command`: özel komut (örn. farklı venv için `"python3 -m maigret"`)
- `integrations.maigret.top_sites`: `--top-sites` limiti
- `integrations.maigret.timeout`: Maigret request timeout (saniye)
- `integrations.maigret.retries`: retry sayısı
- `integrations.maigret.all_sites`: `true` ise `--all-sites`

Örnek:

```yaml
integrations:
  maigret:
    enabled: true
    command: null
    top_sites: 50
    timeout: 12
    retries: 1
    all_sites: false
```

Ortam değişkeni override’ları:

- `OSINT_MAIGRET_ENABLED=true|false`
- `OSINT_MAIGRET_COMMAND="python3 -m maigret"`

Örnek:

```yaml
api:
  rate_limit: "60/minute"

security:
  enabled: true
  api_keys:
    - "change-me-prod-key"
  protect_read_endpoints: true
  audit_logging: true
  jwt:
    enabled: true
    secret: "change-me-jwt-secret"
    rbac_enabled: true
    users:
      - username: admin
        password: change-me
        roles: [admin]

cache:
  enabled: true
  type: redis
  url: redis://localhost:6379/0

queue:
  mode: redis
  redis_url: redis://localhost:6379/0
  redis_pending_key: osint:queue:scan:pending
  redis_processing_key: osint:queue:scan:processing
  redis_events_channel: osint:events:ws
  reserve_timeout_seconds: 5
  worker_lease_seconds: 45
  worker_heartbeat_interval_seconds: 10
  requeue_inflight_on_worker_start: true
  stale_job_recovery_on_worker_start: true
  stale_job_recovery_action: requeue

logging:
  level: INFO
  console: true
  rotate: true
  max_bytes: 10485760
  backup_count: 5
  file: osint_framework.log
```

API key header varsayılanı: `X-API-Key`

JWT kullanımı:

```bash
# token al
curl -X POST http://127.0.0.1:8000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"change-me"}'

# auth context kontrolü
curl http://127.0.0.1:8000/api/v1/auth/me \
  -H "Authorization: Bearer <token>"
```

## AI Özet (Opsiyonel)

Varsayılan olarak framework, tarama sonunda Ollama üzerinden kısa bir özet üretmeyi dener.

- Ollama yoksa tarama başarısız olmaz.
- Sonuçta `correlated_intel.summary` alanında açıklayıcı fallback mesajı görünür.

Opsiyonel ortam değişkenleri:

- `OLLAMA_API_URL` (varsayılan: `http://localhost:11434/api/generate`)
- `LLM_MODEL` (varsayılan: `llama3`)

## Konfigürasyon

Ana ayar dosyası: `osint_framework/config.yaml`

- Dosya yoksa güvenli varsayılanlarla (SQLite + localhost API ayarları) açılır.
- SQLite schema, eksik bazı kolonlar için otomatik uyumluluk migrasyonu uygular.
- `OSINT_QUEUE_MODE` ve `OSINT_REDIS_URL` ile Redis queue ayarları ortamdan override edilebilir.
- Ek queue override'ları:
- `OSINT_QUEUE_WORKER_LEASE_SECONDS`
- `OSINT_QUEUE_WORKER_HEARTBEAT_INTERVAL_SECONDS`
- `OSINT_QUEUE_STALE_JOB_RECOVERY_ACTION` (`requeue` / `error`)
- `OSINT_REDIS_EVENTS_CHANNEL`
- logging override'ları:
  - `OSINT_LOG_LEVEL`
  - `OSINT_LOG_FILE`
  - `OSINT_LOG_CONSOLE`
  - `OSINT_LOG_ROTATE`
  - `OSINT_LOG_MAX_BYTES`
  - `OSINT_LOG_BACKUP_COUNT`

## Alembic Migration

Baseline migration eklidir (`alembic/versions/...initial_schema.py`).

```bash
# mevcut veritabanına migration uygula
osint_framework/venv/bin/alembic -c alembic.ini upgrade head

# farklı DB URL ile çalıştır (örn. test)
ALEMBIC_DATABASE_URL='sqlite+aiosqlite:////tmp/osint_test.db' \
  osint_framework/venv/bin/alembic -c alembic.ini upgrade head
```

Not: macOS `._*` metadata dosyaları Alembic revizyon yüklemeyi bozabilir; `alembic/env.py`
çalışırken bunları otomatik temizler.

## Testler

```bash
osint_framework/venv/bin/python -m unittest discover -s tests -v
```

## Yasal Uyarı

Bu araç yalnızca yetkili güvenlik araştırmaları ve etik kullanım için tasarlanmıştır.

## Vision OSINT (V2)

Yeni `image` target tipi için V2 pipeline aktif:

`image -> face detection -> face crop -> face embedding -> similarity search -> reverse image search -> result URLs -> entity extraction`

### API Kullanımı

Dosya yükleyerek image scan başlatma:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scan/image \
  -F "file=@/absolute/path/suspect.jpg" \
  -F "case_id=1"
```

JSON scan endpoint'i `image` target_type ile URL/path de kabul eder:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"https://example.com/suspect.jpg","target_type":"image"}'
```

### Similarity Search

V2 ile yüz embedding'leri yerel similarity index'e yazılır ve yeni taramalarda benzer yüzler eşleştirilir.

- Match metriği: cosine similarity
- Çıktı alanları: `similarity`, `similarity_matches_total`, `similarity_matches`
- Index varsayılanı: `osint_framework/data/vision/face_similarity_index.json`

### Vision Ayarları

`config.yaml` veya environment üzerinden:

- `OSINT_VISION_ENABLED`
- `OSINT_VISION_UPLOAD_DIR`
- `OSINT_VISION_MAX_UPLOAD_MB`
- `OSINT_VISION_REVERSE_MAX_RESULTS`
- `OSINT_VISION_SCRAPER_MAX_PAGES`
- `OSINT_VISION_ENABLE_EMBEDDING`
- `OSINT_VISION_ENABLE_SIMILARITY`
- `OSINT_VISION_SIMILARITY_MIN_SCORE`
- `OSINT_VISION_SIMILARITY_TOP_K`
- `OSINT_VISION_SIMILARITY_INDEX_PATH`
- `OSINT_VISION_SIMILARITY_MAX_ITEMS`
- `GOOGLE_VISION_API_KEY` (otomatik reverse-image URL keşfi için opsiyonel)

Not: `deepface` yoksa embedding aşaması deterministic descriptor fallback ile devam eder; pipeline kırılmaz.
