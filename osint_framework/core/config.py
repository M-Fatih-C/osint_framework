import yaml
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional
import os

class EngineConfig(BaseModel):
    threads: int = 20
    timeout: int = 15
    retries: int = 3

class CacheConfig(BaseModel):
    enabled: bool = True
    type: str = "in_memory"
    url: Optional[str] = None
    ttl: str = "24h"

class DatabaseConfig(BaseModel):
    url: str

class ProxyConfig(BaseModel):
    enabled: bool = False
    rotation: str = "round_robin"
    list_file: Optional[str] = None
    types: List[str] = Field(default_factory=lambda: ["http"])

class ApiConfig(BaseModel):
    rate_limit: str = "100/minute"
    port: int = 8000
    host: str = "0.0.0.0"


class QueueConfig(BaseModel):
    mode: str = "in_process"  # in_process | redis
    redis_url: str = "redis://localhost:6379/0"
    redis_pending_key: str = "osint:queue:scan:pending"
    redis_processing_key: str = "osint:queue:scan:processing"
    reserve_timeout_seconds: int = 5
    requeue_inflight_on_worker_start: bool = True
    enabled_for_api: bool = True

class JWTUserConfig(BaseModel):
    username: str
    password: str
    roles: List[str] = Field(default_factory=lambda: ["viewer"])
    disabled: bool = False


class JWTSecurityConfig(BaseModel):
    enabled: bool = False
    secret: Optional[str] = None
    algorithm: str = "HS256"
    issuer: str = "osint_framework"
    access_token_ttl_minutes: int = 60
    rbac_enabled: bool = False
    users: List[JWTUserConfig] = Field(default_factory=list)


class SecurityConfig(BaseModel):
    enabled: bool = False
    api_keys: List[str] = Field(default_factory=list)
    api_key_header: str = "X-API-Key"
    protect_read_endpoints: bool = False
    exempt_paths: List[str] = Field(
        default_factory=lambda: [
            "/",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/static",
            "/api/v1/auth/token",
        ]
    )
    trust_x_forwarded_for: bool = False
    audit_logging: bool = True
    jwt: JWTSecurityConfig = Field(default_factory=JWTSecurityConfig)

class LoggingConfig(BaseModel):
    level: str = "INFO"
    file: Optional[str] = None


class MaigretIntegrationConfig(BaseModel):
    enabled: bool = True
    command: Optional[str] = None
    top_sites: int = 50
    timeout: int = 12
    retries: int = 1
    json_report_type: str = "simple"
    all_sites: bool = False
    no_progressbar: bool = True
    no_color: bool = True
    no_recursion: bool = True
    no_extracting: bool = True


class IntegrationsConfig(BaseModel):
    maigret: MaigretIntegrationConfig = Field(default_factory=MaigretIntegrationConfig)

class AppConfig(BaseModel):
    engine: EngineConfig = Field(default_factory=EngineConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    database: DatabaseConfig = Field(
        default_factory=lambda: DatabaseConfig(url="sqlite+aiosqlite:///./osintdb.db")
    )
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    api: ApiConfig = Field(default_factory=ApiConfig)
    queue: QueueConfig = Field(default_factory=QueueConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    integrations: IntegrationsConfig = Field(default_factory=IntegrationsConfig)

def load_config(config_path: str = "config.yaml") -> AppConfig:
    path = Path(config_path)
    if not path.is_absolute() and not path.exists():
        package_path = Path(__file__).resolve().parents[1] / config_path
        if package_path.exists():
            path = package_path
    if not path.exists():
        raise FileNotFoundError(f"Configuration file {config_path} not found.")
    
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    # Targeted env overrides for distributed queue/worker deployment.
    queue_data = data.setdefault("queue", {})
    if os.getenv("OSINT_QUEUE_MODE"):
        queue_data["mode"] = os.getenv("OSINT_QUEUE_MODE")
    if os.getenv("OSINT_REDIS_URL"):
        queue_data["redis_url"] = os.getenv("OSINT_REDIS_URL")
    if os.getenv("OSINT_REDIS_PENDING_KEY"):
        queue_data["redis_pending_key"] = os.getenv("OSINT_REDIS_PENDING_KEY")
    if os.getenv("OSINT_REDIS_PROCESSING_KEY"):
        queue_data["redis_processing_key"] = os.getenv("OSINT_REDIS_PROCESSING_KEY")
    if os.getenv("OSINT_QUEUE_RESERVE_TIMEOUT_SECONDS"):
        try:
            queue_data["reserve_timeout_seconds"] = int(
                os.getenv("OSINT_QUEUE_RESERVE_TIMEOUT_SECONDS", "5")
            )
        except ValueError:
            pass
        
    return AppConfig(**data)

# Singleton configuration instance
try:
    settings = load_config()
except FileNotFoundError:
    settings = AppConfig()
