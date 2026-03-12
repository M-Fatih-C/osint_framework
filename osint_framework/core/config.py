import os
from pathlib import Path
from typing import List, Optional

import yaml
from pydantic import BaseModel, Field


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
    cors_allowed_origins: List[str] = Field(default_factory=lambda: ["*"])
    cors_allow_credentials: bool = False
    cors_allowed_methods: List[str] = Field(default_factory=lambda: ["*"])
    cors_allowed_headers: List[str] = Field(default_factory=lambda: ["*"])


class QueueConfig(BaseModel):
    mode: str = "in_process"  # in_process | redis
    redis_url: str = "redis://localhost:6379/0"
    redis_pending_key: str = "osint:queue:scan:pending"
    redis_processing_key: str = "osint:queue:scan:processing"
    redis_events_channel: str = "osint:events:ws"
    reserve_timeout_seconds: int = 5
    worker_lease_seconds: int = 45
    worker_heartbeat_interval_seconds: int = 10
    requeue_inflight_on_worker_start: bool = True
    stale_job_recovery_on_worker_start: bool = True
    stale_job_recovery_action: str = "requeue"  # requeue | error
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
    console: bool = True
    rotate: bool = True
    max_bytes: int = 10 * 1024 * 1024
    backup_count: int = 5


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


class VisionIntegrationConfig(BaseModel):
    enabled: bool = True
    upload_dir: str = "osint_framework/data/vision/uploads"
    max_upload_mb: int = 15
    reverse_max_results: int = 30
    scraper_max_pages: int = 8
    face_detection_min_confidence: float = 0.35
    face_detection_min_size_px: int = 40
    face_detection_iou_threshold: float = 0.45
    face_detection_max_faces: int = 10
    face_detection_allow_full_image_fallback: bool = True
    face_crop_padding_ratio: float = 0.18
    face_crop_square: bool = True
    enable_embedding: bool = True
    embedding_max_faces: int = 5
    embedding_force_top_face: bool = True
    enable_similarity_search: bool = True
    similarity_min_score: float = 0.82
    similarity_top_k: int = 5
    similarity_index_path: str = "osint_framework/data/vision/face_similarity_index.json"
    similarity_max_items: int = 5000


class IntegrationsConfig(BaseModel):
    maigret: MaigretIntegrationConfig = Field(default_factory=MaigretIntegrationConfig)
    vision: VisionIntegrationConfig = Field(default_factory=VisionIntegrationConfig)


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

    def _parse_csv_env(value: str) -> List[str]:
        return [item.strip() for item in (value or "").split(",") if item.strip()]

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
    if os.getenv("OSINT_REDIS_EVENTS_CHANNEL"):
        queue_data["redis_events_channel"] = os.getenv("OSINT_REDIS_EVENTS_CHANNEL")
    if os.getenv("OSINT_QUEUE_RESERVE_TIMEOUT_SECONDS"):
        try:
            queue_data["reserve_timeout_seconds"] = int(
                os.getenv("OSINT_QUEUE_RESERVE_TIMEOUT_SECONDS", "5")
            )
        except ValueError:
            pass
    if os.getenv("OSINT_QUEUE_WORKER_LEASE_SECONDS"):
        try:
            queue_data["worker_lease_seconds"] = int(
                os.getenv("OSINT_QUEUE_WORKER_LEASE_SECONDS", "45")
            )
        except ValueError:
            pass
    if os.getenv("OSINT_QUEUE_WORKER_HEARTBEAT_INTERVAL_SECONDS"):
        try:
            queue_data["worker_heartbeat_interval_seconds"] = int(
                os.getenv("OSINT_QUEUE_WORKER_HEARTBEAT_INTERVAL_SECONDS", "10")
            )
        except ValueError:
            pass
    if os.getenv("OSINT_QUEUE_STALE_JOB_RECOVERY_ACTION"):
        queue_data["stale_job_recovery_action"] = os.getenv(
            "OSINT_QUEUE_STALE_JOB_RECOVERY_ACTION"
        )

    api_data = data.setdefault("api", {})
    if os.getenv("OSINT_API_RATE_LIMIT"):
        api_data["rate_limit"] = os.getenv("OSINT_API_RATE_LIMIT")
    if os.getenv("OSINT_CORS_ALLOWED_ORIGINS"):
        api_data["cors_allowed_origins"] = _parse_csv_env(
            os.getenv("OSINT_CORS_ALLOWED_ORIGINS", "")
        )
    if os.getenv("OSINT_CORS_ALLOW_CREDENTIALS") is not None:
        api_data["cors_allow_credentials"] = os.getenv(
            "OSINT_CORS_ALLOW_CREDENTIALS", ""
        ).strip().lower() in {"1", "true", "yes", "on"}
    if os.getenv("OSINT_CORS_ALLOWED_METHODS"):
        api_data["cors_allowed_methods"] = _parse_csv_env(
            os.getenv("OSINT_CORS_ALLOWED_METHODS", "")
        )
    if os.getenv("OSINT_CORS_ALLOWED_HEADERS"):
        api_data["cors_allowed_headers"] = _parse_csv_env(
            os.getenv("OSINT_CORS_ALLOWED_HEADERS", "")
        )

    logging_data = data.setdefault("logging", {})
    if os.getenv("OSINT_LOG_LEVEL"):
        logging_data["level"] = os.getenv("OSINT_LOG_LEVEL")
    if os.getenv("OSINT_LOG_FILE"):
        logging_data["file"] = os.getenv("OSINT_LOG_FILE")
    if os.getenv("OSINT_LOG_CONSOLE") is not None:
        logging_data["console"] = os.getenv("OSINT_LOG_CONSOLE", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
    if os.getenv("OSINT_LOG_ROTATE") is not None:
        logging_data["rotate"] = os.getenv("OSINT_LOG_ROTATE", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
    if os.getenv("OSINT_LOG_MAX_BYTES"):
        try:
            logging_data["max_bytes"] = int(os.getenv("OSINT_LOG_MAX_BYTES", "10485760"))
        except ValueError:
            pass
    if os.getenv("OSINT_LOG_BACKUP_COUNT"):
        try:
            logging_data["backup_count"] = int(os.getenv("OSINT_LOG_BACKUP_COUNT", "5"))
        except ValueError:
            pass

    integrations_data = data.setdefault("integrations", {})
    vision_data = integrations_data.setdefault("vision", {})
    if os.getenv("OSINT_VISION_ENABLED") is not None:
        vision_data["enabled"] = os.getenv("OSINT_VISION_ENABLED", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
    if os.getenv("OSINT_VISION_UPLOAD_DIR"):
        vision_data["upload_dir"] = os.getenv("OSINT_VISION_UPLOAD_DIR")
    if os.getenv("OSINT_VISION_MAX_UPLOAD_MB"):
        try:
            vision_data["max_upload_mb"] = int(os.getenv("OSINT_VISION_MAX_UPLOAD_MB", "15"))
        except ValueError:
            pass
    if os.getenv("OSINT_VISION_REVERSE_MAX_RESULTS"):
        try:
            vision_data["reverse_max_results"] = int(
                os.getenv("OSINT_VISION_REVERSE_MAX_RESULTS", "30")
            )
        except ValueError:
            pass
    if os.getenv("OSINT_VISION_SCRAPER_MAX_PAGES"):
        try:
            vision_data["scraper_max_pages"] = int(
                os.getenv("OSINT_VISION_SCRAPER_MAX_PAGES", "8")
            )
        except ValueError:
            pass
    if os.getenv("OSINT_VISION_FACE_MIN_CONFIDENCE"):
        try:
            vision_data["face_detection_min_confidence"] = float(
                os.getenv("OSINT_VISION_FACE_MIN_CONFIDENCE", "0.35")
            )
        except ValueError:
            pass
    if os.getenv("OSINT_VISION_FACE_MIN_SIZE_PX"):
        try:
            vision_data["face_detection_min_size_px"] = int(
                os.getenv("OSINT_VISION_FACE_MIN_SIZE_PX", "40")
            )
        except ValueError:
            pass
    if os.getenv("OSINT_VISION_FACE_IOU_THRESHOLD"):
        try:
            vision_data["face_detection_iou_threshold"] = float(
                os.getenv("OSINT_VISION_FACE_IOU_THRESHOLD", "0.45")
            )
        except ValueError:
            pass
    if os.getenv("OSINT_VISION_FACE_MAX_FACES"):
        try:
            vision_data["face_detection_max_faces"] = int(
                os.getenv("OSINT_VISION_FACE_MAX_FACES", "10")
            )
        except ValueError:
            pass
    if os.getenv("OSINT_VISION_FACE_ALLOW_FULL_IMAGE_FALLBACK") is not None:
        vision_data["face_detection_allow_full_image_fallback"] = os.getenv(
            "OSINT_VISION_FACE_ALLOW_FULL_IMAGE_FALLBACK", ""
        ).strip().lower() in {"1", "true", "yes", "on"}
    if os.getenv("OSINT_VISION_FACE_CROP_PADDING_RATIO"):
        try:
            vision_data["face_crop_padding_ratio"] = float(
                os.getenv("OSINT_VISION_FACE_CROP_PADDING_RATIO", "0.18")
            )
        except ValueError:
            pass
    if os.getenv("OSINT_VISION_FACE_CROP_SQUARE") is not None:
        vision_data["face_crop_square"] = os.getenv(
            "OSINT_VISION_FACE_CROP_SQUARE", ""
        ).strip().lower() in {"1", "true", "yes", "on"}
    if os.getenv("OSINT_VISION_ENABLE_EMBEDDING") is not None:
        vision_data["enable_embedding"] = os.getenv(
            "OSINT_VISION_ENABLE_EMBEDDING", ""
        ).strip().lower() in {"1", "true", "yes", "on"}
    if os.getenv("OSINT_VISION_EMBEDDING_MAX_FACES"):
        try:
            vision_data["embedding_max_faces"] = int(
                os.getenv("OSINT_VISION_EMBEDDING_MAX_FACES", "5")
            )
        except ValueError:
            pass
    if os.getenv("OSINT_VISION_EMBEDDING_FORCE_TOP_FACE") is not None:
        vision_data["embedding_force_top_face"] = os.getenv(
            "OSINT_VISION_EMBEDDING_FORCE_TOP_FACE", ""
        ).strip().lower() in {"1", "true", "yes", "on"}
    if os.getenv("OSINT_VISION_ENABLE_SIMILARITY") is not None:
        vision_data["enable_similarity_search"] = os.getenv(
            "OSINT_VISION_ENABLE_SIMILARITY", ""
        ).strip().lower() in {"1", "true", "yes", "on"}
    if os.getenv("OSINT_VISION_SIMILARITY_MIN_SCORE"):
        try:
            vision_data["similarity_min_score"] = float(
                os.getenv("OSINT_VISION_SIMILARITY_MIN_SCORE", "0.82")
            )
        except ValueError:
            pass
    if os.getenv("OSINT_VISION_SIMILARITY_TOP_K"):
        try:
            vision_data["similarity_top_k"] = int(
                os.getenv("OSINT_VISION_SIMILARITY_TOP_K", "5")
            )
        except ValueError:
            pass
    if os.getenv("OSINT_VISION_SIMILARITY_INDEX_PATH"):
        vision_data["similarity_index_path"] = os.getenv("OSINT_VISION_SIMILARITY_INDEX_PATH")
    if os.getenv("OSINT_VISION_SIMILARITY_MAX_ITEMS"):
        try:
            vision_data["similarity_max_items"] = int(
                os.getenv("OSINT_VISION_SIMILARITY_MAX_ITEMS", "5000")
            )
        except ValueError:
            pass

    return AppConfig(**data)


# Singleton configuration instance
try:
    settings = load_config()
except FileNotFoundError:
    settings = AppConfig()
