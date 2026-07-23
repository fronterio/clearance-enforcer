# n8n-nodes-fronterio-clearance

n8n community node for the Fronterio **Model Clearance API**. Drop a
"Model Clearance" node before your model node: it checks the call against your
organisation's routing policy and returns **green / yellow / red** with reasons
and approved alternatives — optionally stopping the workflow on red.
**Fronterio decides; your workflow enforces.**

## Install

n8n → Settings → Community Nodes → Install → `n8n-nodes-fronterio-clearance`

## Credentials

"Fronterio API": base URL (default `https://fronterio.com`) + an API key with
the `policy_decision` scope.

## Node parameters

- **Model** — register model ID or name (e.g. `DeepSeek V4 Flash`)
- **Data Classes** — what the payload contains (tag honestly)
- **Agent Reference** — optional; a Fronterio agent UUID scopes agent rules
- **Stop Workflow on Red** — on by default

The decision is appended to each item as `fronterioClearance`
(`verdict`, `decisionId`, `reasons`, `unmetConditions`, `recommendedAlternatives`) —
branch on it with an IF node for yellow-handling.

This node calls the REST check endpoint per execution (n8n workflows are not a
hot path); the local-bundle evaluation lives in the LiteLLM/OpenClaw packages.

MIT © Fronterio
