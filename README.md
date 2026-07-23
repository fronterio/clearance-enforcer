# Clearance Enforcer

[![CI](https://github.com/fronterio/clearance-enforcer/actions/workflows/ci.yml/badge.svg)](https://github.com/fronterio/clearance-enforcer/actions/workflows/ci.yml)

Open-source enforcement plugins for the **[Fronterio](https://fronterio.com) Model Clearance API**.

> **Fronterio decides — your runtime enforces.**
> Your prompts never leave your infrastructure toward Fronterio. The platform signs the
> rulebook (a TTL'd, JWS-signed policy bundle); these plugins evaluate every model call
> **locally** in your own stack and send back **metadata-only receipts** — model, data
> classes, verdict, policy version. Never content.

## What this solves

Your organisation has rules like *"the fast model for member data, the frontier model
only for trained staff, nothing personal to non-EU endpoints"*. Fronterio's
**Model & Data Routing Policy** makes those rules structured and evaluable
(green / yellow / red per data class). These plugins are the enforcement point:
they fetch your signed policy bundle, evaluate each call before it happens, block
red verdicts, and stream decision receipts back as compliance evidence — so
"every model call was policy-checked" is a provable statement, not a hope.

## Packages

| Package | Runtime | What it does |
|---|---|---|
| [`fronterio-litellm`](packages/fronterio-litellm) | Python / [LiteLLM](https://github.com/BerriAI/litellm) proxy | Pre-call hook: local bundle evaluation, block/warn/receipt on every call through your gateway |
| [`openclaw-clearance`](packages/openclaw-clearance) | Node / OpenClaw or any TS runtime | `ClearanceClient` with local evaluator, JWS verification (WebCrypto), receipts batcher |
| [`n8n-nodes-fronterio-clearance`](packages/n8n-nodes-fronterio-clearance) | [n8n](https://n8n.io) | "Model Clearance" node: policy check step before your model node, stop-on-red |

## How it works

```
┌────────────────┐  GET /api/v1/model-use/bundle    ┌────────────────┐
│   Fronterio    │ ───────────────────────────────▶ │  Your runtime  │
│ (signs policy) │   signed bundle, 6h TTL          │  (enforces)    │
│                │ ◀─────────────────────────────── │  local eval,   │
└────────────────┘  POST /api/v1/model-use/receipts │ sub-ms, offline│
                     metadata only — never prompts  └────────────────┘
```

- **Fail semantics:** default **fail-open** — if the bundle expires and can't be
  refreshed, calls go through and their receipts are flagged `failedOpen` (loudly
  visible in your Fronterio decision log). Organisations on Business+ can opt into
  **fail-closed** (block until a fresh bundle is available); the mode rides the
  bundle itself.
- **Signature:** bundles are ES256 JWS-signed. Pin the public key in plugin config
  to verify offline and prove exactly which policy version was enforced.
- **Data classes are caller-tagged.** The enforcer verifies policy, not content —
  tag honestly (`public`, `internal`, `customer_data`, `personal_data`,
  `special_category`, `financial`, `credentials`).

## Requirements

A Fronterio organisation on **Business** or **Enterprise** (or a design-partner
arrangement) and an API key with the `policy_decision` scope
(Settings → API Keys). Full API contract:
[Model Clearance API docs](https://github.com/fronterio/Fronterio/blob/main/docs/integrations/policy-decision-api.md)
· [fronterio.com](https://fronterio.com).

## Status

`0.1.x` — pre-release, under live validation with design partners. Contracts may
move until `1.0`. Issues and PRs welcome.

## License

[MIT](LICENSE) © Fronterio
