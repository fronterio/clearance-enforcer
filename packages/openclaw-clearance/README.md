# openclaw-clearance

Fronterio Clearance Enforcer for OpenClaw and any Node/TypeScript runtime.
Local policy-bundle evaluation, offline ES256 JWS verification (WebCrypto) and
metadata-only decision receipts — **Fronterio decides; your runtime enforces.**

## Install

```bash
npm install openclaw-clearance
```

## Use

```ts
import { ClearanceClient, ClearanceBlockedError } from "openclaw-clearance";

const clearance = new ClearanceClient({
  apiKey: process.env.FRONTERIO_API_KEY!,      // scope: policy_decision
  agentRef: "member-support-bot",              // optional
  bundlePublicKeyPem: process.env.FRONTERIO_BUNDLE_PUBLIC_KEY, // optional pin
  onYellow: "warn",                            // or "block"
});

// Before every model call:
try {
  const verdict = await clearance.check("DeepSeek V4 Flash", ["personal_data"]);
  // verdict.light === "green" | "yellow"; alternatives in verdict.recommendedAlternatives
} catch (err) {
  if (err instanceof ClearanceBlockedError) {
    // red verdict (or fail-closed on an expired bundle) — do not call the model
  }
}

// On shutdown:
await clearance.flushReceipts();
```

As an OpenClaw skill: instantiate one `ClearanceClient` in your skill's setup and
call `check()` in the pre-invocation step of every model-calling tool; map
`ClearanceBlockedError` to your skill's refusal path.

## Behaviour

Same contract as the LiteLLM plugin: local evaluation against the signed 6h-TTL
bundle; fail-open with `failedOpen`-flagged receipts by default, org-configurable
fail-closed at Business+; receipts are metadata-only (never prompt content).

MIT © Fronterio
