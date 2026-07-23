"""LiteLLM pre-call hook: enforce your Fronterio Model Clearance policy.

Usage (LiteLLM proxy config.yaml):

    litellm_settings:
      callbacks:
        - fronterio_clearance.litellm_hook.clearance_hook

Environment:
    FRONTERIO_API_KEY            required — API key with the policy_decision scope
    FRONTERIO_BASE_URL           default https://fronterio.com
    FRONTERIO_AGENT_REF          optional — agent reference logged on every receipt
    FRONTERIO_BUNDLE_PUBLIC_KEY  optional — SPKI PEM to verify bundle signatures
    FRONTERIO_LITERACY_COMPLETED optional — "true" to attest AI-literacy completion
    FRONTERIO_ON_YELLOW          "warn" (default) or "block"

Tag data classes per request via LiteLLM metadata:

    litellm.completion(..., metadata={"fronterio_data_classes": ["personal_data"]})

Untagged requests default to ["internal"] — tag honestly; the enforcer
verifies policy, not content. Prompt content NEVER leaves your runtime
toward Fronterio: the policy bundle comes down, metadata receipts go up.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from .client import ClearanceBlockedError, ClearanceClient, ClearanceConfig

_client: Optional[ClearanceClient] = None


def _get_client() -> ClearanceClient:
    global _client
    if _client is None:
        api_key = os.environ.get("FRONTERIO_API_KEY")
        if not api_key:
            raise RuntimeError("FRONTERIO_API_KEY is not set")
        _client = ClearanceClient(ClearanceConfig(
            api_key=api_key,
            base_url=os.environ.get("FRONTERIO_BASE_URL", "https://fronterio.com"),
            agent_ref=os.environ.get("FRONTERIO_AGENT_REF"),
            bundle_public_key_pem=os.environ.get("FRONTERIO_BUNDLE_PUBLIC_KEY"),
            literacy_completed=os.environ.get(
                "FRONTERIO_LITERACY_COMPLETED", "").lower() == "true",
            on_yellow=os.environ.get("FRONTERIO_ON_YELLOW", "warn"),
        ))
    return _client


async def clearance_hook(user_api_key_dict: Any, cache: Any,
                         data: dict, call_type: str) -> dict:
    """LiteLLM async_pre_call_hook-compatible entry point."""
    metadata = data.get("metadata") or {}
    data_classes = metadata.get("fronterio_data_classes") or ["internal"]
    attestations = metadata.get("fronterio_attestations") or []

    try:
        verdict = _get_client().check(
            model=data.get("model", ""),
            data_classes=list(data_classes),
            attestations=list(attestations),
        )
    except ClearanceBlockedError:
        raise

    metadata["fronterio_clearance"] = {
        "verdict": verdict.light,
        "unmetConditions": verdict.unmet_conditions,
        "alternatives": verdict.recommended_alternatives,
    }
    data["metadata"] = metadata
    return data
