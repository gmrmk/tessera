"""clients  -  deterministic mock extraction, prompt parsing, token accounting."""
from __future__ import annotations

import asyncio

from dual_log_engine.clients import MockLLMClient, TokenUsage, estimate_tokens
from dual_log_engine.prompts import format_distillation_prompt


def test_mock_default_extract_is_deterministic():
    prompt = format_distillation_prompt("auth.py refresh failed: upstream timeout error")
    a = asyncio.run(MockLLMClient().distill(prompt))
    b = asyncio.run(MockLLMClient().distill(prompt))
    assert a.entities == b.entities and a.relations == b.relations


def test_mock_default_extract_produces_both_tiers():
    prompt = format_distillation_prompt("Parser.py crashed: NullPointer exception while parsing")
    result = asyncio.run(MockLLMClient().distill(prompt))
    levels = {e["level"] for e in result.entities}
    assert {"LOW", "HIGH"} <= levels
    # an error line with a component yields a CAUSES edge
    assert any(r["relation_type"] == "CAUSES" for r in result.relations)


def test_scripted_mock_returns_the_script():
    script = lambda batch: (
        [{"entity_name": "x", "entity_type": "COMPONENT", "description": "d", "level": "LOW"}],
        [],
    )
    result = asyncio.run(MockLLMClient(script=script).distill(format_distillation_prompt("anything")))
    assert [e["entity_name"] for e in result.entities] == ["x"]
    assert result.relations == []


def test_batch_is_extracted_from_the_prompt_of_record():
    prompt = format_distillation_prompt("THE-RAW-BATCH-MARKER")
    assert MockLLMClient._batch_from_prompt(prompt).strip() == "THE-RAW-BATCH-MARKER"


def test_token_usage_compression_ratio():
    assert TokenUsage(input_tokens=20, output_tokens=0).compression_ratio is None
    u = TokenUsage(input_tokens=25, output_tokens=0, raw_input_tokens=100)
    assert u.compression_ratio == 0.75
    assert u.total == 25


def test_estimate_tokens_is_nonzero_and_grows_with_length():
    assert estimate_tokens("") == 1
    assert estimate_tokens("a" * 400) > estimate_tokens("a" * 40)
