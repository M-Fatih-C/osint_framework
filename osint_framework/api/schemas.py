import ipaddress
import re
import unicodedata
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{2,64}$")
PHONE_RE = re.compile(r"^\+?[0-9][0-9\-\s()]{5,24}$")

class ScanRequest(BaseModel):
    target: str = Field(..., description="The target to scan (e.g., example.com, admin@example.com)")
    case_id: Optional[int] = Field(
        default=None,
        ge=1,
        description="Optional case ID to associate this scan/job with.",
    )
    target_type: Literal["domain", "email", "ip", "username", "phone", "person_name"] = Field(
        ...,
        description="Type of target: domain, email, ip, username, phone, or person_name.",
    )

    @field_validator("target")
    @classmethod
    def normalize_target(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("target cannot be empty")
        return value

    @model_validator(mode="after")
    def validate_target_by_type(self):
        target = self.target
        if self.target_type == "ip":
            try:
                ipaddress.ip_address(target)
            except ValueError as exc:
                raise ValueError("Invalid IP address") from exc
        elif self.target_type == "domain":
            if not DOMAIN_RE.match(target.lower()):
                raise ValueError("Invalid domain name")
        elif self.target_type == "email":
            if "@" not in target or target.count("@") != 1:
                raise ValueError("Invalid email address")
            local, domain = target.rsplit("@", 1)
            if not local or not DOMAIN_RE.match(domain.lower()):
                raise ValueError("Invalid email address")
        elif self.target_type == "username":
            if not USERNAME_RE.match(target):
                raise ValueError(
                    "Invalid username format. Use a username/handle (e.g. fatihcetin) without spaces."
                )
        elif self.target_type == "phone":
            if not PHONE_RE.match(target):
                raise ValueError("Invalid phone number format")
        elif self.target_type == "person_name":
            if not _is_valid_person_name(target):
                raise ValueError(
                    "Invalid person name format. Use letters with spaces (e.g. Muhammet Fatih Cetintas)."
                )
        return self


def _is_valid_person_name(value: str) -> bool:
    if not (2 <= len(value) <= 120):
        return False

    has_letter = False
    for ch in value:
        if ch.isalpha():
            has_letter = True
            continue
        if ch in " .'-":
            continue
        # Allow combining marks for some unicode input methods.
        if unicodedata.category(ch).startswith("M"):
            continue
        return False

    if not has_letter:
        return False

    # Reject repeated separators like "--" or "''" and names starting/ending with separators.
    compact = value.strip()
    if not compact:
        return False
    if compact[0] in ".-'" or compact[-1] in ".-'":
        return False
    if any(pair in compact for pair in ["--", "''", ".."]):
        return False
    return True

class ScanResponse(BaseModel):
    job_id: str
    status: str
    case_id: Optional[int] = None


class AuthTokenRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class AuthTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    roles: List[str]
    username: str


class AuthMeResponse(BaseModel):
    authenticated: bool
    auth_type: Optional[str] = None
    subject: Optional[str] = None
    roles: List[str] = Field(default_factory=list)

class StatusResponse(BaseModel):
    job_id: str
    case_id: Optional[int] = None
    target: str
    target_type: str
    status: str
    modules_done: int
    modules_total: int
    error_message: Optional[str] = None

class ResultResponse(BaseModel):
    job_id: str
    case_id: Optional[int] = None
    target: str
    target_type: str
    status: str
    modules_done: int = 0
    modules_total: int = 0
    results: List[Dict[str, Any]]
    correlated_intel: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None

class ModuleInfo(BaseModel):
    name: str
    version: str
    description: str
    target_types: List[str]
    author: str

class AuditLogEntry(BaseModel):
    id: int
    created_at: Optional[str] = None
    request_id: str
    method: str
    path: str
    status_code: int
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    duration_ms: int
    api_key_used: bool
    note: Optional[str] = None

class AuditLogListResponse(BaseModel):
    items: List[AuditLogEntry]
    count: int


class CaseCreateRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    description: Optional[str] = Field(default=None, max_length=4000)
    tags: List[str] = Field(default_factory=list, max_length=30)
    status: Literal["open", "closed", "on_hold"] = "open"
    priority: Literal["low", "normal", "high", "critical"] = "normal"

    @field_validator("title")
    @classmethod
    def normalize_title(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 3:
            raise ValueError("title must be at least 3 characters")
        return value

    @field_validator("description")
    @classmethod
    def normalize_description(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        value = value.strip()
        return value or None

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, tags: List[str]) -> List[str]:
        normalized: List[str] = []
        seen = set()
        for raw in tags:
            tag = raw.strip()
            if not tag:
                continue
            if len(tag) > 64:
                raise ValueError("tag length must be <= 64")
            key = tag.lower()
            if key in seen:
                continue
            seen.add(key)
            normalized.append(tag)
        return normalized


class CaseNoteCreateRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=4000)
    author: Optional[str] = Field(default=None, max_length=120)

    @field_validator("content")
    @classmethod
    def normalize_content(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("content cannot be empty")
        return value

    @field_validator("author")
    @classmethod
    def normalize_author(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        value = value.strip()
        return value or None


class CaseCounts(BaseModel):
    scans: int = 0
    targets: int = 0
    notes: int = 0


class CaseSummary(BaseModel):
    id: int
    title: str
    description: Optional[str] = None
    status: str
    priority: str
    tags: List[str] = Field(default_factory=list)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    counts: CaseCounts


class CaseListResponse(BaseModel):
    items: List[CaseSummary]
    count: int


class CaseTrackedTarget(BaseModel):
    id: int
    target: str
    target_type: str
    first_seen_at: Optional[str] = None
    last_seen_at: Optional[str] = None


class CaseJobSummary(BaseModel):
    job_id: str
    target: str
    target_type: str
    status: str
    modules_total: int = 0
    created_at: Optional[str] = None
    completed_at: Optional[str] = None


class CaseNoteResponse(BaseModel):
    id: int
    content: str
    author: Optional[str] = None
    created_at: Optional[str] = None


class CaseDetailResponse(CaseSummary):
    tracked_targets: List[CaseTrackedTarget] = Field(default_factory=list)
    recent_jobs: List[CaseJobSummary] = Field(default_factory=list)
    notes: List[CaseNoteResponse] = Field(default_factory=list)

class SystemStatusResponse(BaseModel):
    status: str
    workers_active: int
    jobs_running: int
    modules_loaded: int
    queue_mode: Optional[str] = None
    queue_pending: Optional[int] = None
    queue_processing: Optional[int] = None
    queue_error: Optional[str] = None
