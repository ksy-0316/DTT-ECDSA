"""Analytic communication-delay model (Section VI-A of the paper).

    "Communication is modelled on typical V2I and V2V conditions in vehicular
     networks (DSRC and C-V2X). The single-hop link latency is set to 2 ms and
     the effective bandwidth to 6 Mbps, so transmitting a message of s bytes
     costs 2 + 8s/(6 x 10^3) ms.  This delay is accumulated analytically and
     folded into the timing window of the corresponding phase, which keeps the
     measurement deterministic and free from the coarse granularity of the
     Windows timer."

Every latency reported by this implementation is therefore an end-to-end value
that already contains the transmission overhead:

    phase_latency = measured_cpu_time + sum_of_all_link_delays_of_that_phase
"""

from __future__ import annotations

from dataclasses import dataclass, field

LINK_LATENCY_MS = 2.0      # single-hop DSRC / C-V2X latency
BANDWIDTH_MBPS = 6.0       # effective bandwidth


def tx_ms(nbytes: int) -> float:
    """Cost in ms of pushing ``nbytes`` over one single-hop link."""
    return LINK_LATENCY_MS + 8.0 * nbytes / (BANDWIDTH_MBPS * 1000.0)


@dataclass
class Channel:
    """Accumulates every inter-entity message of one protocol phase."""

    total_ms: float = 0.0
    total_bytes: int = 0
    log: list = field(default_factory=list)

    def send(self, src: str, dst: str, label: str, nbytes: int, count: int = 1) -> float:
        """Register ``count`` identical messages of ``nbytes`` from ``src`` to ``dst``."""
        cost = count * tx_ms(nbytes)
        self.total_ms += cost
        self.total_bytes += count * nbytes
        self.log.append((src, dst, label, nbytes, count, cost))
        return cost

    def report(self) -> str:
        lines = [
            f"    {src:>7s} -> {dst:<7s} | {label:<34s} | "
            f"{nbytes:6d} B x {count:3d} = {cost:9.3f} ms"
            for src, dst, label, nbytes, count, cost in self.log
        ]
        lines.append(f"    {'':>7s}    {'':<7s} | {'TOTAL':<34s} | "
                     f"{self.total_bytes:6d} B       = {self.total_ms:9.3f} ms")
        return "\n".join(lines)
