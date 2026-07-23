/**
 * Fronterio Clearance Enforcer — OpenClaw / generic TypeScript package.
 *
 * Fronterio decides — your runtime enforces. The package fetches the org's
 * signed policy bundle, evaluates every model use LOCALLY (your prompts never
 * leave your infrastructure toward Fronterio), and batches metadata-only
 * decision receipts back as compliance evidence.
 *
 * Wire it as an OpenClaw skill/middleware, or call `checkClearance()` from any
 * Node runtime before invoking a model. MIT licensed.
 */

import { evaluate, type PolicyBundle, type Verdict } from "./evaluator";

export * from "./evaluator";

export interface ClearanceOptions {
  apiKey: string;
  baseUrl?: string;
  agentRef?: string | null;
  /** SPKI PEM to verify bundle JWS signatures offline. Omit to accept unsigned. */
  bundlePublicKeyPem?: string | null;
  literacyCompleted?: boolean;
  /** "warn" (default) or "block" on yellow verdicts. */
  onYellow?: "warn" | "block";
}

export class ClearanceBlockedError extends Error {
  constructor(message: string, public readonly verdict: Verdict | null = null) {
    super(message);
    this.name = "ClearanceBlockedError";
  }
}

interface Receipt {
  bundleId: string;
  ruleId: string | null;
  verdict: string;
  model: string;
  dataClasses: string[];
  agentRef: string | null;
  decidedAt: string;
  failedOpen: boolean;
  enforcer: string;
}

const RECEIPT_FLUSH_SIZE = 20;
const ENFORCER = "openclaw-clearance/0.1.0";

function base64UrlToBytes(segment: string): Uint8Array<ArrayBuffer> {
  const padded = segment.replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(new ArrayBuffer(raw.length));
  for (let i = 0; i < raw.length; i += 1) bytes[i] = raw.charCodeAt(i);
  return bytes;
}

/** Verify a compact ES256 JWS with WebCrypto and return the bundle payload. */
export async function verifyBundleJws(jws: string, publicKeyPem: string): Promise<PolicyBundle> {
  const [headerB64, payloadB64, sigB64] = jws.split(".");
  const header = JSON.parse(new TextDecoder().decode(base64UrlToBytes(headerB64)));
  if (header.alg !== "ES256") throw new Error(`Unexpected JWS alg: ${header.alg}`);

  const pemBody = publicKeyPem
    .replace(/-----BEGIN PUBLIC KEY-----/, "")
    .replace(/-----END PUBLIC KEY-----/, "")
    .replace(/\s+/g, "");
  const keyRaw = atob(pemBody);
  const keyBytes = new Uint8Array(new ArrayBuffer(keyRaw.length));
  for (let i = 0; i < keyRaw.length; i += 1) keyBytes[i] = keyRaw.charCodeAt(i);
  const key = await crypto.subtle.importKey(
    "spki",
    keyBytes,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    base64UrlToBytes(sigB64),
    new TextEncoder().encode(`${headerB64}.${payloadB64}`),
  );
  if (!valid) throw new Error("Bundle JWS signature verification failed");
  return JSON.parse(new TextDecoder().decode(base64UrlToBytes(payloadB64))) as PolicyBundle;
}

export class ClearanceClient {
  private bundle: PolicyBundle | null = null;
  private receipts: Receipt[] = [];
  private readonly baseUrl: string;

  constructor(private readonly options: ClearanceOptions) {
    this.baseUrl = (options.baseUrl ?? "https://fronterio.com").replace(/\/$/, "");
  }

  private bundleExpired(bundle: PolicyBundle): boolean {
    return Date.now() >= new Date(bundle.expiresAt).getTime();
  }

  private async fetchBundle(): Promise<PolicyBundle> {
    const res = await fetch(`${this.baseUrl}/api/v1/model-use/bundle`, {
      headers: { Authorization: `Bearer ${this.options.apiKey}` },
    });
    if (!res.ok) throw new Error(`Bundle fetch failed: ${res.status}`);
    const body = (await res.json()) as { bundle: PolicyBundle; jws: string | null };
    if (this.options.bundlePublicKeyPem && body.jws) {
      return verifyBundleJws(body.jws, this.options.bundlePublicKeyPem);
    }
    return body.bundle;
  }

  /** Returns [bundle, stale] — stale means refresh failed past expiry. */
  async getBundle(): Promise<[PolicyBundle | null, boolean]> {
    if (this.bundle && !this.bundleExpired(this.bundle)) return [this.bundle, false];
    try {
      this.bundle = await this.fetchBundle();
      return [this.bundle, false];
    } catch {
      return [this.bundle, true];
    }
  }

  /**
   * Evaluate a call locally, record a receipt, and enforce:
   * throws ClearanceBlockedError on red (and yellow with onYellow="block",
   * and on stale bundles under fail-closed).
   */
  async check(model: string, dataClasses: string[], attestations: string[] = []): Promise<Verdict> {
    const [bundle, stale] = await this.getBundle();

    if (bundle && stale && bundle.failMode === "closed") {
      throw new ClearanceBlockedError("Policy bundle unavailable and fail mode is closed");
    }
    if (!bundle) {
      // Never had a bundle: fail open, but the receipt flags it loudly.
      await this.record(null, model, dataClasses, "yellow", null, true);
      return {
        light: "yellow",
        reasons: [{ code: "no_rule_for_class" }],
        unmetConditions: [],
        matchedRuleIds: [],
        recommendedAlternatives: [],
      };
    }

    const verdict = evaluate(bundle, model, dataClasses, {
      agentId: this.options.agentRef ?? null,
      literacyCompleted: this.options.literacyCompleted,
      attestations,
    });
    await this.record(bundle, model, dataClasses, verdict.light, verdict.matchedRuleIds[0] ?? null, stale);

    if (verdict.light === "red") {
      throw new ClearanceBlockedError(
        `Blocked by model routing policy: ${JSON.stringify(verdict.reasons)}`,
        verdict,
      );
    }
    if (verdict.light === "yellow" && this.options.onYellow === "block") {
      throw new ClearanceBlockedError(
        `Yellow verdict and onYellow=block: ${verdict.unmetConditions.join(", ")}`,
        verdict,
      );
    }
    return verdict;
  }

  private async record(
    bundle: PolicyBundle | null,
    model: string,
    dataClasses: string[],
    verdict: string,
    ruleId: string | null,
    failedOpen: boolean,
  ): Promise<void> {
    this.receipts.push({
      bundleId: bundle?.bundleId ?? "unknown",
      ruleId,
      verdict,
      model,
      dataClasses,
      agentRef: this.options.agentRef ?? null,
      decidedAt: new Date().toISOString(),
      failedOpen,
      enforcer: ENFORCER,
    });
    if (this.receipts.length >= RECEIPT_FLUSH_SIZE) await this.flushReceipts();
  }

  /** Best-effort receipt delivery — never blocks or fails the caller. */
  async flushReceipts(): Promise<void> {
    const batch = this.receipts.splice(0, 500);
    if (batch.length === 0) return;
    try {
      await fetch(`${this.baseUrl}/api/v1/model-use/receipts`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.options.apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ receipts: batch }),
      });
    } catch {
      this.receipts.unshift(...batch);
    }
  }
}

/** One-shot convenience: create a client per call site or share one instance. */
export async function checkClearance(
  options: ClearanceOptions,
  model: string,
  dataClasses: string[],
  attestations: string[] = [],
): Promise<Verdict> {
  return new ClearanceClient(options).check(model, dataClasses, attestations);
}
