from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class ProviderResult:
    provider: str
    status: str = "ok"  # ok, error, skipped
    payload: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == "ok" and not self.error

    def to_module_output(self, include_status: bool = True) -> Dict[str, Any]:
        data = dict(self.payload or {})
        data.setdefault("provider", self.provider)
        if include_status and "status" not in data:
            data["status"] = self.status
        if self.error and "error" not in data:
            data["error"] = self.error
        if self.meta:
            data["provider_meta"] = dict(self.meta)
        return data
