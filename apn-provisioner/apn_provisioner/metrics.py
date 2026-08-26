"""In-memory counters (spec 5.7). Rendered to the log periodically and on exit."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field


@dataclass
class Metrics:
    attaches_seen: int = 0
    correlations_resolved: int = 0
    guti_unresolved: int = 0
    sends: int = 0
    failures: int = 0
    skips: Counter = field(default_factory=Counter)

    def skip(self, reason: str) -> None:
        self.skips[reason] += 1

    def render(self) -> str:
        skip_str = ", ".join(f"{k}={v}" for k, v in sorted(self.skips.items()))
        return (
            f"attaches_seen={self.attaches_seen} "
            f"correlations_resolved={self.correlations_resolved} "
            f"guti_unresolved={self.guti_unresolved} "
            f"sends={self.sends} failures={self.failures} "
            f"skips[{skip_str}]"
        )
