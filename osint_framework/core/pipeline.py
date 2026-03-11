from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Protocol


@dataclass
class PipelineContext:
    """Mutable context bag passed between pipeline stages."""

    target: str
    target_type: str
    data: Dict[str, Any] = field(default_factory=dict)
    artifacts: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)

    def add_event(self, stage: str, status: str, detail: str = "") -> None:
        self.events.append({"stage": stage, "status": status, "detail": detail})


class PipelineStage(Protocol):
    name: str

    async def run(self, context: PipelineContext) -> None:
        """Mutate context in-place."""


class PipelineRunner:
    """Tiny sequential pipeline runner for OSINT stage orchestration."""

    def __init__(self, stages: List[PipelineStage]):
        self.stages = list(stages)

    async def execute(self, context: PipelineContext) -> PipelineContext:
        for stage in self.stages:
            context.add_event(stage.name, "started")
            try:
                await stage.run(context)
                context.add_event(stage.name, "completed")
            except Exception as exc:
                context.add_event(stage.name, "error", str(exc))
                raise
        return context
