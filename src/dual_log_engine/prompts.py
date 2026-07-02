"""The distillation prompt  -  verbatim from the spec.

This is the exact dual-level extraction prompt the eviction worker sends to the
LLM (mock or real). It instructs the model to split extraction into LOW
(operational) and HIGH (conceptual) tiers and to return the strict
entities/relations JSON schema that ``graph_store`` ingests.

Kept in its own module so the prompt-of-record is a single, reviewable string
that an audit reader can diff against what actually got sent.
"""
from __future__ import annotations

# Braces in the JSON schema are doubled so str.format only substitutes {batch}.
DISTILLATION_PROMPT_TEMPLATE = """Task: Parse raw operational traces into a unified entity-relation knowledge map.
You must extract structures across TWO distinct levels of abstraction:
1. LOW Level: Granular components, explicit error types, runtime variables, and immediate programmatic fixes.
2. HIGH Level: Structural design principles, sweeping architectural failure patterns, and permanent engineering guidelines.

Format constraints: Return clean, valid JSON matching exactly this structural schema:
{{
  "entities": [{{"entity_name": "string", "entity_type": "string", "description": "string", "level": "LOW|HIGH"}}],
  "relations": [{{"source": "string", "target": "string", "relation_type": "string", "description": "string", "level": "LOW|HIGH"}}]
}}

Raw Telemetry Corpus:
{batch}
"""


def format_distillation_prompt(batch: str) -> str:
    """Insert a raw log batch into the distillation prompt-of-record."""

    return DISTILLATION_PROMPT_TEMPLATE.format(batch=batch)
