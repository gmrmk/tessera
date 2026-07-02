"""EpisodicLogStore  -  the short-lived raw-trace buffer with eviction.

Holds raw execution traces only briefly, then evicts them so the buffer stays
small and the durable record lives in the distilled graph instead. This is the
doctrine's *sunset* asymmetry made concrete: raw episodic logs expire; the
distilled semantic graph persists.

Eviction is per ``(tenant_id, repo_id)`` group  -  each repo independently keeps
its **last 20 traces or a 48-hour rolling window**, whichever is tighter. The
clock is injectable (``now_fn``) so the age window is deterministically testable.

The store stays a pure data structure: ``append`` returns the evicted traces and
(optionally) fires an ``on_evict`` callback. It does *not* know about asyncio  - 
the caller wires ``on_evict`` to the worker's ``schedule`` so distillation runs
off the main loop. That keeps ingestion non-blocking without coupling the buffer
to the worker.
"""
from __future__ import annotations

import time
from typing import Callable, Optional

from .envelope import EpisodicTrace, MemoryEnvelope

GroupKey = tuple[str, str]  # (tenant_id, repo_id)

DEFAULT_MAX_TRACES = 20
DEFAULT_MAX_AGE_SECONDS = 48 * 3600  # 48-hour rolling window

EvictHandler = Callable[[str, str, list[EpisodicTrace]], None]


class EpisodicLogStore:
    def __init__(
        self,
        max_traces: int = DEFAULT_MAX_TRACES,
        max_age_seconds: float = DEFAULT_MAX_AGE_SECONDS,
        now_fn: Callable[[], float] = time.time,
        on_evict: Optional[EvictHandler] = None,
    ) -> None:
        self.max_traces = max_traces
        self.max_age_seconds = max_age_seconds
        self._now = now_fn
        self._on_evict = on_evict
        self._buffers: dict[GroupKey, list[EpisodicTrace]] = {}

    def append(self, envelope: MemoryEnvelope) -> list[EpisodicTrace]:
        """Buffer a raw trace; return (and fire the callback for) anything evicted."""
        key: GroupKey = (envelope["tenant_id"], envelope["repo_id"])
        trace: EpisodicTrace = envelope["payload"]  # type: ignore[assignment]
        self._buffers.setdefault(key, []).append(trace)
        evicted = self._evict(key)
        if evicted and self._on_evict is not None:
            self._on_evict(key[0], key[1], evicted)
        return evicted

    def _evict(self, key: GroupKey) -> list[EpisodicTrace]:
        buf = self._buffers[key]
        cutoff = self._now() - self.max_age_seconds

        # 1) age window: drop traces older than the cutoff
        fresh = [t for t in buf if t["ts"] >= cutoff]
        aged_out = [t for t in buf if t["ts"] < cutoff]

        # 2) count cap: keep the most-recent max_traces (arrival order), evict the rest
        if len(fresh) > self.max_traces:
            overflow = fresh[: -self.max_traces]
            keep = fresh[-self.max_traces :]
        else:
            overflow = []
            keep = fresh

        self._buffers[key] = keep
        return aged_out + overflow

    def buffer(self, tenant_id: str, repo_id: str) -> list[EpisodicTrace]:
        """Current retained traces for a group (a copy)."""
        return list(self._buffers.get((tenant_id, repo_id), []))

    # --- persistence support (used by MemoryEngine to share buffers on disk) - #

    def snapshot(self) -> dict[GroupKey, list[EpisodicTrace]]:
        """A deep-ish copy of every group's buffer, for serialisation."""
        return {k: list(v) for k, v in self._buffers.items()}

    def restore(self, buffers: dict[GroupKey, list[EpisodicTrace]]) -> None:
        """Replace all buffers (e.g. from a persisted snapshot)."""
        self._buffers = {k: list(v) for k, v in buffers.items()}

    def clear(self, tenant_id: str, repo_id: str) -> None:
        """Drop a group's buffer (e.g. after a forced flush/distill)."""
        self._buffers.pop((tenant_id, repo_id), None)
