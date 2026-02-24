# OSINT Framework

FastAPI tabanlı, plugin mimarili, gerçek zamanlı dashboard içeren modüler OSINT aracı.

## Özellikler

- `FastAPI` REST API + `WebSocket` canlı durum iletimi
- Plugin registry ile hedef tipine göre modül seçimi
- Asenkron worker pool ile paralel modül çalıştırma
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
├── run.py                         # Repo kökünden API başlatma
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
└── tests/                         # Regression testleri
```

## Kurulum

```bash
python3 -m venv osint_framework/venv
source osint_framework/venv/bin/activate
pip install -r requirements.txt
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
- `WS /ws` -> canlı durum bildirimleri

### Örnek istekler

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com","target_type":"domain"}'

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
