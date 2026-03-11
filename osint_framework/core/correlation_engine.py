from typing import Any, Dict, List, Optional

from osint_framework.core.correlation import Correlator


class CorrelationEngine:
    """Compatibility facade for a dedicated correlation-engine naming scheme."""

    @staticmethod
    def analyze(
        results: List[Dict[str, Any]],
        *,
        target: Optional[str] = None,
        target_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        return Correlator.analyze(results, target=target, target_type=target_type)
