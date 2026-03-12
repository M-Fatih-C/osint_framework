from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol


@dataclass
class PipelineContext:
    """Mutable context bag passed between pipeline stages."""

    target: str
    target_type: str
    data: Dict[str, Any] = field(default_factory=dict)
    artifacts: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)

    def add_event(
        self,
        stage: str,
        status: str,
        detail: str = "",
        meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        event = {"stage": stage, "status": status, "detail": detail}
        if meta:
            event.update(meta)
        self.events.append(event)


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
            started_at_ms = int(time.time() * 1000)
            context.add_event(stage.name, "started", meta={"at_ms": started_at_ms})
            try:
                await stage.run(context)
                completed_at_ms = int(time.time() * 1000)
                context.add_event(
                    stage.name,
                    "completed",
                    meta={
                        "at_ms": completed_at_ms,
                        "duration_ms": max(0, completed_at_ms - started_at_ms),
                    },
                )
            except Exception as exc:
                errored_at_ms = int(time.time() * 1000)
                context.add_event(
                    stage.name,
                    "error",
                    str(exc),
                    meta={
                        "at_ms": errored_at_ms,
                        "duration_ms": max(0, errored_at_ms - started_at_ms),
                    },
                )
                raise
        return context
