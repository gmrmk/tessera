"""IO seam  -  the LLM client protocol, a deterministic mock, and opt-in adapters.

The engine never calls a remote API directly. It depends only on the ``LLMClient``
*protocol*; the default implementation (``MockLLMClient``) is deterministic and
in-process, so the whole package compiles and the self-check runs with no
network and no API key (the spec's "compiles cleanly out of the box").

The real adapters (``AnthropicLLMClient``, ``HeadroomLLMClient``) live here too,
but every third-party import is done *lazily inside the method*  -  importing this
module pulls in nothing beyond the standard library and the typed records.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Protocol, runtime_checkable

from .envelope import Entity, Relation


@dataclass
class TokenUsage:
    """Token accounting for one distillation call.

    ``raw_input_tokens`` is populated only when a compression layer (Headroom)
    sat in front of the call  -  it records what the prompt *would* have cost
    uncompressed, so the audit ledger can show the saving.
    """

    input_tokens: int = 0
    output_tokens: int = 0
    raw_input_tokens: int | None = None  # pre-compression size, if a compressor ran

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens

    @property
    def compression_ratio(self) -> float | None:
        """Fraction of input tokens saved by compression, or None if not compressed."""
        if self.raw_input_tokens and self.raw_input_tokens > 0:
            return 1.0 - (self.input_tokens / self.raw_input_tokens)
        return None


@dataclass
class DistillResult:
    """What a distillation call returns: the extracted graph plus token usage."""

    entities: list[Entity]
    relations: list[Relation]
    usage: TokenUsage


@runtime_checkable
class LLMClient(Protocol):
    """The only thing the eviction worker depends on. Implementations may be
    mock, Anthropic-backed, Headroom-wrapped, or anything else schema-shaped."""

    async def distill(self, prompt: str) -> DistillResult: ...


# --- token estimation (shared, intentionally crude) ------------------------- #

def estimate_tokens(text: str) -> int:
    # ponytail: ~4 chars/token heuristic. Good enough for audit/accounting in
    # the mock path; a real client reports the provider's exact counts instead.
    return max(1, len(text) // 4)


# --- the default, deterministic mock ---------------------------------------- #

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_.]+")
_ERROR_WORDS = ("error", "exception", "fail", "fatal", "panic", "traceback")
_FIX_WORDS = ("fix", "resolve", "patch", "mitigat")


def _slug(text: str, limit: int = 32) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:limit] or "trace"


def _default_extract(batch: str) -> tuple[list[Entity], list[Relation]]:
    """Deterministically derive a dual-level entity/relation graph from raw text.

    Rules (stable, no randomness  -  same input always yields the same output):
      LOW tier
        * the first identifier-ish token on a line  -> COMPONENT entity
        * any error/exception keyword on a line      -> ERROR_TYPE entity
        * component + error on the same line         -> CAUSES edge
        * + a fix keyword on that line               -> RESOLVES edge
      HIGH tier (one level-consistent pair per batch, so HIGH queries return
      something connected rather than dangling against LOW nodes)
        * a PRINCIPLE entity and a SUBSYSTEM entity, joined by a DEPENDS_ON edge
    """
    entities: dict[str, Entity] = {}
    relations: list[Relation] = []
    components: list[str] = []

    for line in (ln.strip() for ln in batch.splitlines()):
        if not line:
            continue
        toks = _IDENT.findall(line)
        comp = next((t for t in toks if ("." in t) or t[:1].isupper()), None)
        lower = line.lower()
        has_error = any(w in lower for w in _ERROR_WORDS)
        has_fix = any(w in lower for w in _FIX_WORDS)

        if comp:
            components.append(comp)
            entities.setdefault(
                comp,
                Entity(entity_name=comp, entity_type="COMPONENT",
                       description=f"component referenced in trace: {line}", level="LOW"),
            )
        if has_error:
            err = f"error::{_slug(line)}"
            entities.setdefault(
                err,
                Entity(entity_name=err, entity_type="ERROR_TYPE", description=line, level="LOW"),
            )
            if comp:
                relations.append(Relation(source=comp, target=err, relation_type="CAUSES",
                                          description=f"{comp} surfaced {err}", weight=1, level="LOW"))
                if has_fix:
                    relations.append(Relation(source=comp, target=err, relation_type="RESOLVES",
                                              description=f"{comp} resolved {err}", weight=1, level="LOW"))

    if components:
        top = max(sorted(set(components)), key=components.count)
        principle = "principle::stabilize-recurring-failure"
        subsystem = f"subsystem::{_slug(top)}"
        entities[principle] = Entity(
            entity_name=principle, entity_type="COMPONENT",
            description="recurring failure pattern distilled into a structural guideline", level="HIGH")
        entities[subsystem] = Entity(
            entity_name=subsystem, entity_type="COMPONENT",
            description=f"the subsystem around {top}, viewed at architectural altitude", level="HIGH")
        relations.append(Relation(source=principle, target=subsystem, relation_type="DEPENDS_ON",
                                  description=f"the guideline governs the {top} subsystem", weight=1, level="HIGH"))

    return list(entities.values()), relations


class MockLLMClient:
    """Deterministic, in-process stand-in for the distillation LLM.

    Pass ``script`` to return a canned ``(entities, relations)`` for full control
    in tests; otherwise the built-in deterministic extractor runs over the raw
    batch embedded in the prompt.
    """

    def __init__(
        self,
        script: Callable[[str], tuple[list[Entity], list[Relation]]] | None = None,
    ) -> None:
        self._script = script

    @staticmethod
    def _batch_from_prompt(prompt: str) -> str:
        # The prompt-of-record ends with "Raw Telemetry Corpus:\n<batch>".
        marker = "Raw Telemetry Corpus:"
        return prompt.split(marker, 1)[1].strip() if marker in prompt else prompt

    async def distill(self, prompt: str) -> DistillResult:
        batch = self._batch_from_prompt(prompt)
        entities, relations = self._script(batch) if self._script else _default_extract(batch)
        usage = TokenUsage(
            input_tokens=estimate_tokens(prompt),
            output_tokens=estimate_tokens(str(entities) + str(relations)),
        )
        return DistillResult(entities=entities, relations=relations, usage=usage)


# --- optional real adapters (lazy imports; not used in v1 tests/demo) -------- #

# Model choice: per the user's directive, distillation runs on **Opus 4.8**
# (`claude-opus-4-8`)  -  the deepest-reasoning model  -  to maximize the quality of
# the permanent principles extracted, not to minimize cost. Trade-off: Opus is
# $5/$25 per MTok vs Haiku's $1/$5, so pair it with HeadroomLLMClient to compress
# the batch and offset the input cost ("maxx the tokens, not the credit card").
# Strict JSON comes from the structured-outputs feature (`output_config.format`
# of type `json_schema`), which is GA on Opus 4.8; prefill is rejected with a 400
# on current models. SDK package: `anthropic` (PyPI).
ANTHROPIC_MODEL = "claude-opus-4-8"

_DISTILL_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "entities": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "entity_name": {"type": "string"},
                    "entity_type": {"type": "string"},
                    "description": {"type": "string"},
                    "level": {"type": "string", "enum": ["LOW", "HIGH"]},
                },
                "required": ["entity_name", "entity_type", "description", "level"],
            },
        },
        "relations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "source": {"type": "string"},
                    "target": {"type": "string"},
                    "relation_type": {"type": "string"},
                    "description": {"type": "string"},
                    "level": {"type": "string", "enum": ["LOW", "HIGH"]},
                },
                "required": ["source", "target", "relation_type", "description", "level"],
            },
        },
    },
    "required": ["entities", "relations"],
}


class AnthropicLLMClient:
    """Opt-in real distillation via Claude Opus 4.8 structured outputs.

    Requires ``pip install dual-log-engine[llm]``. Imported lazily so this module
    has no hard dependency on ``anthropic``. Not exercised by the v1 test suite.
    """

    def __init__(self, model: str = ANTHROPIC_MODEL, max_tokens: int = 4096) -> None:
        self.model = model
        self.max_tokens = max_tokens

    async def distill(self, prompt: str) -> DistillResult:  # pragma: no cover - needs network
        import json

        from anthropic import AsyncAnthropic  # lazy: optional dependency

        client = AsyncAnthropic()
        resp = await client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            messages=[{"role": "user", "content": prompt}],
            # Structured outputs: constrained decoding guarantees schema-valid JSON.
            output_config={"format": {"type": "json_schema", "schema": _DISTILL_JSON_SCHEMA}},
        )
        text = "".join(block.text for block in resp.content if getattr(block, "type", "") == "text")
        data = json.loads(text)
        # trust-but-verify: coerce shape and default the fields the model may omit;
        # never assume the model obeyed the schema even with constrained decoding.
        entities: list[Entity] = [
            Entity(
                entity_name=e.get("entity_name", ""),
                entity_type=e.get("entity_type", ""),
                description=e.get("description", ""),
                level=e.get("level", "LOW"),
            )
            for e in data.get("entities", [])
        ]
        relations: list[Relation] = [
            Relation(
                source=r.get("source", ""),
                target=r.get("target", ""),
                relation_type=r.get("relation_type", ""),
                description=r.get("description", ""),
                weight=1,
                level=r.get("level", "LOW"),
            )
            for r in data.get("relations", [])
        ]
        usage = TokenUsage(
            input_tokens=getattr(resp.usage, "input_tokens", 0),
            output_tokens=getattr(resp.usage, "output_tokens", 0),
        )
        return DistillResult(entities=entities, relations=relations, usage=usage)


class HeadroomLLMClient:
    """Opt-in wrapper that compresses the prompt via Headroom before delegating.

    "Maxx the tokens, not the credit card": Headroom shrinks the raw log batch so
    the downstream model bills far fewer input tokens; the saving is recorded in
    ``TokenUsage.raw_input_tokens`` for the audit ledger. Requires
    ``pip install dual-log-engine[headroom]``. Imported lazily; not used in v1.
    """

    def __init__(self, inner: LLMClient) -> None:
        self._inner = inner

    async def distill(self, prompt: str) -> DistillResult:  # pragma: no cover - needs headroom-ai
        from headroom import compress  # lazy: optional dependency

        raw_tokens = estimate_tokens(prompt)
        compressed = compress([{"role": "user", "content": prompt}])
        compressed_text = compressed[-1]["content"] if isinstance(compressed, list) else str(compressed)
        result = await self._inner.distill(compressed_text)
        result.usage.raw_input_tokens = raw_tokens
        result.usage.input_tokens = estimate_tokens(compressed_text)
        return result
