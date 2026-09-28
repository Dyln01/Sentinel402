# Sentinel402 — Usage Guide

**Paid tools for AI agents over x402 + MPP.** One endpoint, two payment rails,
one wallet. No API keys, no accounts, no signup — your agent sends a request,
gets an HTTP 402 telling it the exact price, signs a payment with any EVM
wallet, retries, and gets the answer. Every call costs fractions of a cent in
USDC on Base.

> **This repository is the guide.** The code lives in
> **[Dyln01/pii-guard](https://github.com/Dyln01/pii-guard)** (a single
> Cloudflare Worker, zero runtime dependencies). Full protocol docs:
> [`docs/MPP.md`](https://github.com/Dyln01/pii-guard/blob/main/docs/MPP.md) ·
> [`docs/DISCOVERY.md`](https://github.com/Dyln01/pii-guard/blob/main/docs/DISCOVERY.md) ·
> [`docs/RESEARCH.md`](https://github.com/Dyln01/pii-guard/blob/main/docs/RESEARCH.md)

**Live service:** `https://pii-guardrail.sentinel402.workers.dev`

---

## What you can buy

| Surface | What it does | Price |
|---|---|---|
| **PII & secret guardrail** — `POST /v1/scan` | Scan an outbound payload for card numbers, SSNs, emails, phones, IP/MAC, IBANs, routing numbers, crypto wallets, passports, national IDs, DOBs, medical record numbers — and secrets: AWS/GitHub/OpenAI/Stripe/Slack/Google/Twilio keys, JWTs, bearer tokens, PEM private keys, basic-auth URLs, connection strings, password assignments. Returns a verdict (`allow`/`redact`/`block`), a 0–100 risk score, per-rule findings with **redacted** samples, and in `redact` mode a sanitized copy that is structurally identical and safe to forward. | **$0.01** |
| **Live data** — `GET /v1/data/{collection}` | Crypto spot prices (24h change), current weather + today's high/low for any place, the 5 latest commits of a public GitHub repo, live/final sports scores (NBA · NFL · MLB · NHL · EPL · UCL · LaLiga · Serie A · Bundesliga · MLS), ECB daily FX rates. Normalized, citable, cached 30 s–1 h. | **$0.002** |
| **RCP/1 retrieval** — `POST /rcp/retrieve` | The same live data as spec-shaped retrieval `Hit`s with `citation{uri,title}` — drop straight into a RAG context with provenance attached. Handshake methods free. | **$0.002** |
| **MCP tools** — `POST /mcp` | `scan_for_pii` and `get_live_data` as MCP tools over streamable HTTP. `initialize` / `tools/list` / `ping` / `service_info` are free. | **$0.01 / $0.002** |
| **Free trial** — `POST /v1/trial` | The same scan engine, 1,000 chars, 10/day/IP. Try before you pay. | **$0** |

Detection is regex + checksums (Luhn, IBAN mod-97, ABA 3-7-1, SSA issuance
ranges) — no model in the loop, so it cannot hallucinate a finding. 38 rules,
34 on by default; the live catalogue is at `GET /rules`. **Zero retention:**
payloads are scanned in memory and discarded; detected secrets are never
echoed back in plaintext.

---

## How to pay (both rails, one wallet)

Every paid endpoint answers an unpaid request with **HTTP 402 carrying both
challenges at once**. Pick whichever your stack speaks — the price, the USDC
contract and the receiving wallet are identical.

```bash
H=https://pii-guardrail.sentinel402.workers.dev
curl -si -X POST $H/v1/scan -H 'content-type: application/json' -d '{"text":"..."}'
# HTTP/2 402
# PAYMENT-REQUIRED: eyJ4NDAyVmVyc2lv…      <- x402 v2 (base64 JSON)
# WWW-Authenticate: Payment id="…", realm="…", method="evm", intent="charge", …   <- MPP
# X-Payment-Protocol: x402, mpp
# body: {"error":"X-PAYMENT header is required","accepts":[…],"x402Version":1}     <- x402 v1
```

### Rail 1 — x402 (Coinbase's protocol)

1. Read the requirements from the `PAYMENT-REQUIRED` header (v2) or the JSON
   body (v1): `{scheme:"exact", network, amount (atomic USDC), asset, payTo, …}`.
2. Sign an **EIP-3009 `transferWithAuthorization`** from your wallet with a
   **random nonce**, for the exact amount, to `payTo`.
3. Retry the identical request with `PAYMENT-SIGNATURE: <base64 payload>` (v2)
   or `X-PAYMENT` (v1).
4. `200 OK` — receipt in `PAYMENT-RESPONSE` / `X-PAYMENT-RESPONSE`, plus
   `X-Settlement-Tx` and a `body.x402` block with the basescan link.

With the official SDK:

```js
import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { toClientEvmSigner } from "@x402/evm";
import { privateKeyToAccount } from "viem/accounts";

const client = new x402Client();
client.register("eip155:*", new ExactEvmScheme(toClientEvmSigner(privateKeyToAccount(KEY), publicClient)));
const paidFetch = wrapFetchWithPayment(fetch, client);

const res = await paidFetch(`${H}/v1/scan`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ text: outboundPayload, mode: "redact" }),
});
const { decision, sanitized } = await res.json();
```

Legacy v1 clients (`x402-fetch`, `x402-axios`) work unchanged.

### Rail 2 — MPP (Machine Payments Protocol, Tempo × Stripe — [mpp.dev](https://mpp.dev))

The IETF *"Payment" HTTP authentication scheme*. Same EIP-3009 signature —
**the only difference is the nonce**, which binds your payment to the
challenge: `nonce = keccak256(challenge.id + challenge.realm)`.

1. Parse the `WWW-Authenticate: Payment` challenge (`id`, `realm`,
   `method="evm"`, `intent="charge"`, `request` = base64url JCS JSON with
   `amount`/`currency`/`recipient`/`methodDetails`, `digest`, `expires`).
2. Sign `transferWithAuthorization` with the challenge-bound nonce
   (`validBefore` ≤ `expires`).
3. Retry the **byte-identical** request (POST bodies are sha-256 digest-bound)
   with `Authorization: Payment <base64url {challenge, payload, source?}>`.
4. `200 OK` — receipt in the `Payment-Receipt` header
   (`{status:"success", method:"evm", timestamp, reference:<tx>, challengeId, chainId}`).
   Failures come back as `402 + application/problem+json` (RFC 9457) **with a
   fresh challenge**, so you can re-sign immediately.

With the reference SDK (`mppx`), the client fulfils these challenges
automatically — its `evm.charge` method exists precisely for this shape. A
runnable hand-rolled client is in the code repo:
[`examples/mpp-client.mjs`](https://github.com/Dyln01/pii-guard/blob/main/examples/mpp-client.mjs)
(`--inspect` mode explains a live challenge with no wallet needed).

### MCP and RCP

* **MCP** (`POST /mcp`, streamable HTTP): unpaid `tools/call` → HTTP 402 with
  both challenges. Pay via headers, or — per the MPP MCP transport draft — put
  the credential at `params._meta["org.paymentauth/credential"]`; the receipt
  returns at `result._meta["org.paymentauth/receipt"]`. `initialize`
  advertises `capabilities.experimental.payment.methods.evm.intents=["charge"]`,
  and `tools/list` (free) shows every tool's price under
  `_meta["x402/priceUsd"]`.
* **RCP/1** (`POST /rcp/<method>`, JSON-RPC 2.0): `initialize` / `info` /
  `catalog/list` / `ping` are free; `retrieve` is paid through the same gate.

### Gotchas that cost an afternoon

* The `exact` scheme requires the amount to match **exactly** — no over/under-payment.
* x402 headers use **standard base64** (`A-Za-z0-9+/=`); MPP uses **base64url without padding**. Don't mix them.
* `extra.name`/`extra.version` (x402) are the EIP-712 domain (`"USD Coin"`/`"2"` on Base mainnet, `"USDC"`/`"2"` on Base Sepolia) — get them wrong and verification fails silently.
* MPP nonces are **not random**: `keccak256(challenge.id + challenge.realm)`, or the credential is rejected.
* MPP POST challenges bind a body digest — retry with the exact bytes that received the 402.
* 402s are `Cache-Control: no-store`; never cache a price.

---

## Using it as a guardrail (the actual product)

The flagship use: scan **before** any outbound call, so your agent can never
leak a customer's card number or your API keys into a third-party prompt or
webhook.

```js
async function safeSend(url, body) {
  const { decision, sanitized } = await scan(JSON.stringify(body)); // POST /v1/scan, mode:"redact"
  if (decision === "block") throw new Error("Refusing to send: PII detected");
  return fetch(url, { method: "POST", body: sanitized ?? JSON.stringify(body) });
}
```

At $0.01 and ~300 ms, that is cheaper and faster than the mistake it
prevents. The code repo also ships
[`@sentinel402/agent-guardrail`](https://github.com/Dyln01/pii-guard/tree/main/packages/agent-guardrail) —
a zero-dependency `fetch` wrapper that scans, pays, redacts (or refuses)
transparently, with an injectable signer.

### Free taste first

```bash
curl -s -X POST $H/v1/trial -H 'content-type: application/json' \
  -d '{"text":"card 4242 4242 4242 4242, ssn 123-45-6789","mode":"redact"}' | jq
# 1,000 chars, 10/day/IP — the response includes the upgrade path
```

---

## Request/response reference (quick)

`POST /v1/scan`

```jsonc
// request
{
  "text": "string to scan",            // …or…
  "payload": { "any": "JSON" },        // scan an object, get a sanitized clone back
  "mode": "detect | redact | block",   // default "detect"
  "rules": ["CREDIT_CARD", "SSN"],     // optional explicit set (see GET /rules)
  "enable": ["SWIFT_BIC"],             // optional additions to the default profile
  "disable": ["IPV4"],                 // optional removals
  "minSeverity": "critical",           // optional filter
  "blockThreshold": 40                 // risk score that trips "block" mode
}
// response (200)
{
  "ok": true, "decision": "redact", "risk": 100,
  "counts": { "critical": 1, "high": 0, "medium": 0, "low": 0 },
  "findings": [{ "rule": "CREDIT_CARD", "severity": "critical", "confidence": 0.99,
                 "samples": [{ "preview": "[CREDIT_CARD:************4242]" }] }],
  "sanitized": "Charge card [CREDIT_CARD:************4242], thanks.",
  "x402": { "settled": true, "transaction": "0x…", "protocol": "x402|mpp",
            "explorer": "https://basescan.org/tx/0x…" }
}
```

Convenience headers on the 200: `X-Scan-Decision`, `X-Scan-Risk`,
`X-Settlement-Tx`. `GET /v1/data/{collection}` takes per-collection args
(`symbol=BTC`, `place=Berlin`, `repo=owner/name`, `league=NBA`,
`base=USD&quotes=EUR,GBP`) and returns citable `items[]` plus a joined `text`.

---

## Discovery surface (all free — discovery is never paywalled)

For agents, crawlers and catalogs, this service publishes every document the
ecosystem reads, all generated at request time from the same price book as the
paywall (a listing can never disagree with the price):

| Document | Who reads it |
|---|---|
| `GET /openapi.json` | **The canonical contract** — x402scan/agentcash registration (`info.x-guidance`, structured `price`, `protocols: [x402, mpp]`, input/output schemas, declared 402s) and MPP registries (IETF `offers` + `x-service-info`) |
| `GET /.well-known/agent.json` | Open 402 Directory v1.3 (nightly crawler; declares `payments.x402` **and** `payments.mpp` — both badges, one verified payout address) |
| `GET /.well-known/agent-card.json` | A2A (Google Agent2Agent) clients — skills, `securitySchemes` for both rails |
| `GET /.well-known/x402` | x402 crawlers/fallback discovery |
| `GET /.well-known/mpp` | MPP clients; probed by discovery runtimes alongside the x402 well-known |
| `GET /llms.txt` | LLM crawlers and humans pasting the URL into a chat |
| `GET /` · `/prices` · `/rules` · `/health` | Service card, price book, detection catalogue, liveness + config diagnostics |
| `extensions.bazaar` inside each 402 | Coinbase/PayAI/Dexter **Bazaar** catalogs (indexing flips after one settled payment — either rail counts) |

Free handshakes for budgeting before paying: `POST /mcp` `tools/list` (prices
in `_meta`), `POST /rcp/catalog/list`, `GET /v1/data` (collection index),
`GET /prices`.

---

## Security model in one paragraph

Settle **before** responding (no free rides). Local anti-diversion preflight
on both rails: `payTo`/`amount`/`network`/`asset` equality, and for MPP the
HMAC-bound challenge id (spec test vectors), digest-bound bodies, expiry, and
the challenge-bound on-chain nonce — tampered payments are rejected **without
ever calling the facilitator** (no sponsor-gas abuse). Facilitator failover
only on facilitator-side faults, never on a rejected payment (no
facilitator-shopping). A dust floor rejects under-settlements even when the
facilitator says "success". ReDoS-safe bounded-quantifier patterns over
hostile input, body-size caps, fail-open trial rate limiting. Details and
attack-class table: the code repo's README and
[`docs/RESEARCH.md`](https://github.com/Dyln01/pii-guard/blob/main/docs/RESEARCH.md).

---

## Running your own instance

The Worker is MIT-licensed and deploys three ways — paste one file into the
Cloudflare dashboard, `wrangler deploy`, or Git integration (auto-deploy on
push). `wrangler.jsonc` ships pre-configured for **Base mainnet** through
keyless facilitators; the one required edit is `PAY_TO` (your wallet — both
rails pay into it). Testnet dry-run: `NETWORK=base-sepolia` + the x402.org
facilitator + faucet USDC. `/health` returns **503 with the exact reason** if
anything is misconfigured (testnet facilitator on mainnet, price below a
facilitator floor, zero-address wallet…) — it will never silently serve a
paywall that cannot settle.

```bash
git clone https://github.com/Dyln01/pii-guard && cd pii-guard
npm install
npm test                 # 264 unit tests (protocol spec vectors included)
npm run test:integration # 179 end-to-end checks against real workerd
npm run probe            # live facilitator/price viability for YOUR config
npx wrangler deploy
npm run verify:live -- https://<your-worker>.workers.dev
```

Guides: [`docs/DEPLOY.md`](https://github.com/Dyln01/pii-guard/blob/main/docs/DEPLOY.md) ·
[`docs/PASTE-DEPLOY.md`](https://github.com/Dyln01/pii-guard/blob/main/docs/PASTE-DEPLOY.md) ·
[`docs/EARN.md`](https://github.com/Dyln01/pii-guard/blob/main/docs/EARN.md) (monetization & marketplace submissions).

---

## Honest limitations

Regex + checksums cannot find **names, free-text addresses, or undated
birthdays** — that needs a NER model. The correct framing: *catches the
credentials and identifiers that cause reportable breaches, in ~1 ms, for a
fraction of a cent*. Every finding carries a `confidence` so you can set your
own threshold. MPP support covers the `evm`/`charge` method with EIP-3009
`authorization` credentials (the USDC path); `permit2`/`transaction`/`hash`
credential types and non-EVM methods (`tempo`, `stripe`, `solana`, …) are
answered with an actionable `invalid-payload` problem — those rails need a
server-side broadcaster or PSP, which this deliberately keyless Worker is not.

---

*Licence: MIT. Detection patterns draw on conventions popularized by
[Microsoft Presidio](https://microsoft.github.io/presidio/); no code is
copied. x402 is Coinbase's protocol; MPP is the Tempo × Stripe Machine
Payments Protocol — this project implements both from their public specs.*
