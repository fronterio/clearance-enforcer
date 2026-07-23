"""Fronterio Model Clearance client: signed policy bundles + decision receipts.

- Fetches the org's policy bundle (GET /api/v1/model-use/bundle), optionally
  verifies the ES256 JWS against a pinned public key, and caches it until
  `expiresAt`.
- On refresh failure past expiry, applies the bundle's fail semantics:
  fail-open lets calls through and marks their receipts `failedOpen: true`
  (loudly flagged in the Fronterio decision log); fail-closed blocks until a
  fresh bundle is available.
- Batches metadata-only decision receipts to POST /api/v1/model-use/receipts.
  Receipts NEVER contain prompt content — model ref, data classes, verdict,
  bundle id, timestamps only.
"""

from __future__ import annotations

import base64
import json
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import httpx

from .evaluator import Verdict, evaluate

RECEIPT_FLUSH_SIZE = 20
RECEIPT_FLUSH_SECONDS = 30.0


class ClearanceBlockedError(Exception):
    """Raised when the policy blocks a call (red verdict, or fail-closed)."""

    def __init__(self, message: str, verdict: Optional[Verdict] = None):
        super().__init__(message)
        self.verdict = verdict


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def verify_bundle_jws(jws: str, public_key_pem: str) -> dict:
    """Verify a compact ES256 JWS and return the bundle payload.

    Requires `cryptography`. Raises on any verification failure — callers
    treat an invalid signature exactly like a missing bundle.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    header_b64, payload_b64, sig_b64 = jws.split(".")
    header = json.loads(_b64url_decode(header_b64))
    if header.get("alg") != "ES256":
        raise ValueError(f"Unexpected JWS alg: {header.get('alg')}")

    signature = _b64url_decode(sig_b64)
    if len(signature) != 64:
        raise ValueError("Invalid ES256 signature length")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")

    public_key = load_pem_public_key(public_key_pem.encode())
    public_key.verify(  # type: ignore[union-attr]
        encode_dss_signature(r, s),
        f"{header_b64}.{payload_b64}".encode(),
        ec.ECDSA(hashes.SHA256()),
    )
    return json.loads(_b64url_decode(payload_b64))


@dataclass
class ClearanceConfig:
    api_key: str
    base_url: str = "https://fronterio.com"
    agent_ref: Optional[str] = None
    #: Pin Fronterio's bundle-signing public key (SPKI PEM) to verify offline.
    #: None accepts unsigned bundles (e.g. before the platform key is set).
    bundle_public_key_pem: Optional[str] = None
    #: Attest that acting users completed AI literacy training.
    literacy_completed: bool = False
    #: What to do on a yellow verdict: "warn" (default) or "block".
    on_yellow: str = "warn"
    timeout_seconds: float = 5.0


class ClearanceClient:
    """Thread-safe bundle cache + local evaluator + receipts batcher."""

    def __init__(self, config: ClearanceConfig):
        self.config = config
        self._lock = threading.Lock()
        self._bundle: Optional[dict] = None
        self._receipts: list[dict] = []
        self._last_flush = time.monotonic()
        self._http = httpx.Client(
            base_url=config.base_url,
            headers={"Authorization": f"Bearer {config.api_key}"},
            timeout=config.timeout_seconds,
        )

    # ── Bundle lifecycle ────────────────────────────────────────────────

    def _bundle_expired(self, bundle: dict) -> bool:
        expires = bundle.get("expiresAt")
        if not expires:
            return True
        expiry = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        return datetime.now(timezone.utc) >= expiry

    def _fetch_bundle(self) -> dict:
        response = self._http.get("/api/v1/model-use/bundle")
        response.raise_for_status()
        body = response.json()
        if self.config.bundle_public_key_pem and body.get("jws"):
            return verify_bundle_jws(body["jws"], self.config.bundle_public_key_pem)
        return body["bundle"]

    def get_bundle(self) -> tuple[Optional[dict], bool]:
        """Return (bundle, stale). stale=True means refresh failed past expiry."""
        with self._lock:
            cached = self._bundle
        if cached is not None and not self._bundle_expired(cached):
            return cached, False
        try:
            fresh = self._fetch_bundle()
            with self._lock:
                self._bundle = fresh
            return fresh, False
        except Exception:
            return cached, True

    # ── The enforcement decision ────────────────────────────────────────

    def check(self, model: str, data_classes: list[str],
              attestations: Optional[list[str]] = None) -> Verdict:
        """Evaluate a call locally and record a receipt.

        Raises ClearanceBlockedError on red (and on yellow when configured
        to block, and on stale bundles under fail-closed).
        """
        bundle, stale = self.get_bundle()

        if bundle is None or (stale and bundle.get("failMode") == "closed"):
            if bundle is not None and bundle.get("failMode") == "closed":
                raise ClearanceBlockedError(
                    "Policy bundle unavailable and fail mode is closed")
            if bundle is None:
                # Never had a bundle: nothing to evaluate against. Fail open
                # but flag it — the receipt is the loud part.
                self._record(None, model, data_classes, "yellow", failed_open=True)
                return Verdict("yellow")

        verdict = evaluate(
            bundle, model, data_classes,
            agent_id=self.config.agent_ref,
            literacy_completed=self.config.literacy_completed,
            attestations=attestations,
        )
        self._record(bundle, model, data_classes, verdict.light,
                     rule_id=verdict.matched_rule_ids[0] if verdict.matched_rule_ids else None,
                     failed_open=stale)

        if verdict.light == "red":
            raise ClearanceBlockedError(
                f"Blocked by model routing policy: {[r.to_dict() for r in verdict.reasons]}",
                verdict)
        if verdict.light == "yellow" and self.config.on_yellow == "block":
            raise ClearanceBlockedError(
                f"Yellow verdict and on_yellow=block: {verdict.unmet_conditions}",
                verdict)
        return verdict

    # ── Receipts ────────────────────────────────────────────────────────

    def _record(self, bundle: Optional[dict], model: str, data_classes: list[str],
                verdict: str, rule_id: Optional[str] = None,
                failed_open: bool = False) -> None:
        receipt = {
            "bundleId": (bundle or {}).get("bundleId", "unknown"),
            "ruleId": rule_id,
            "verdict": verdict,
            "model": model,
            "dataClasses": data_classes,
            "agentRef": self.config.agent_ref,
            "decidedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "failedOpen": failed_open,
            "enforcer": "fronterio-litellm/0.1.0",
        }
        with self._lock:
            self._receipts.append(receipt)
            should_flush = (len(self._receipts) >= RECEIPT_FLUSH_SIZE
                            or time.monotonic() - self._last_flush > RECEIPT_FLUSH_SECONDS)
        if should_flush:
            self.flush_receipts()

    def flush_receipts(self) -> None:
        """Best-effort receipt delivery — never blocks or fails the caller."""
        with self._lock:
            batch, self._receipts = self._receipts[:500], self._receipts[500:]
            self._last_flush = time.monotonic()
        if not batch:
            return
        try:
            self._http.post("/api/v1/model-use/receipts", json={"receipts": batch})
        except Exception:
            with self._lock:
                self._receipts = batch + self._receipts
