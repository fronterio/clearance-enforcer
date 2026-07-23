# fronterio-litellm

Fronterio Clearance Enforcer for [LiteLLM](https://github.com/BerriAI/litellm).
A pre-call hook that enforces your organisation's Model & Data Routing Policy
locally in your own proxy — **Fronterio decides; your runtime enforces.**
Prompts never leave your infrastructure toward Fronterio.

## Install

```bash
pip install fronterio-litellm            # + [verify] extra for JWS verification
pip install "fronterio-litellm[verify]"
```

## Configure (LiteLLM proxy)

```yaml
# config.yaml
litellm_settings:
  callbacks:
    - fronterio_clearance.litellm_hook.clearance_hook
```

```bash
export FRONTERIO_API_KEY=frk_...           # scope: policy_decision
export FRONTERIO_AGENT_REF=member-support  # optional, logged on receipts
export FRONTERIO_ON_YELLOW=warn            # or: block
# optional — pin the bundle-signing public key (SPKI PEM) for offline verification
export FRONTERIO_BUNDLE_PUBLIC_KEY="$(cat fronterio-bundle-public.pem)"
```

Tag data classes per request (untagged requests default to `["internal"]`):

```python
litellm.completion(
    model="deepseek-v4-flash",
    messages=[...],
    metadata={"fronterio_data_classes": ["personal_data"]},
)
```

## Behaviour

- **green** — call proceeds; receipt recorded.
- **yellow** — proceeds with a warning (or blocks with `FRONTERIO_ON_YELLOW=block`);
  unmet conditions + approved alternatives land in `metadata["fronterio_clearance"]`.
- **red** — raises `ClearanceBlockedError`; the call never reaches the model.
- **Bundle expired & unreachable** — fail-open by default with a `failedOpen`
  receipt; fail-closed if your organisation has opted in (Business+).

Receipts are batched (20 per flush / 30s) and contain metadata only.

## Standalone use (no LiteLLM)

```python
from fronterio_clearance import ClearanceClient, ClearanceConfig

client = ClearanceClient(ClearanceConfig(api_key="frk_..."))
verdict = client.check("DeepSeek V4 Flash", ["personal_data"])
```

MIT © Fronterio
