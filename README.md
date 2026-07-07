# v4call-escrow — the isolated money box (settlement authority)

`v4call-escrow` is the **isolated escrow deployment** for v4call (decoupling handoff item 1;
handover-escrow-core §4/§9). It wraps the `escrow-core` library and makes the **box — not the
node — the money authority**: it holds the **only** active key (`V4CALL_ESCROW_KEY`), its **own**
durable ledger, and is the only place a disbursement is computed and signed. The internet-facing
`v4call-node` becomes a **keyless reporter** that sends signed `event-report`s over
`escrow-protocol/0.1`; the box independently re-verifies each call's payments **on-chain** and
settles. A compromise of the busy node therefore cannot drain funds.

`0.1.0` · depends on `escrow-core@^0.1` (a sibling: `file:../escrow-core`) · transport
`escrow-protocol/0.1` over Nostr (nGate).

## The safety property

The box verifies **every** escrowed payment (ring/connect/deposit/topup) itself
(`escrow-core.verifyPayment`, tx-anchored + exact-memo) and only disburses within that verified
envelope. The split conserves it:

```
payout + refund + fee  ==  ring + connect + deposit − dust   (for ANY rate/fee/duration)
```

So a lying report can only **re-split** a call's verified deposit between caller/callee/platform
— never mint money, never exceed what was actually escrowed. Idempotency (no double-disburse) is
the same two durable guards used in-process today: `tx_id UNIQUE` (replay) + single-winner
`atomicClose` (crash/redelivery/concurrency).

## Disburse resilience (proven live, 2026-07-07)

A payout is never stranded by a flaky network, and never double-paid by a retry:

- A **transient** broadcast failure (or a missing key) leaves the refund row `pending` — only a
  permanent on-chain rejection (bad sig, insufficient balance, RC) is terminal `failed`.
- `disbursePending` retries pending rows on a **60s tick**, and **before every retry** runs
  `findOutgoingByMemo` (on-chain probe): a memo match means a prior attempt landed and its response
  was lost → mark `sent`, never re-broadcast; an inconclusive probe skips the cycle. Broadcasts go
  out via escrow-core's `nativeBroadcast` (offline dhive signing + native-fetch JSON-RPC — dhive's
  bundled node-fetch proved 100% broken on this box).
- **Terminal receipts**: an authorized-but-structurally-bad report (e.g. payment to an account this
  box doesn't hold) gets a signed `status:'failed'` receipt so the node stops republishing it.
  Hard-gate rejections (bad sig / unauthorized reporter) stay silent — no receipt oracle.
- **Completion receipts**: when a ref's last pending payout finally lands, the box publishes a
  refreshed signed receipt — the node upgrades its ledger and tells both parties the money moved.

## Layout

| File | Role |
|---|---|
| `escrow-box.js` | The box core — `createEscrowBox().handleReport(signed)`: hard-gate (verifyReport + authorized reporter + nonce) → verify each payment on-chain → `atomicClose` → `settle` → `adapter.settlementSplit` → `disburse` → signed `settlement-receipt`. Pure + fully injectable. |
| `nostr-transport.mjs` | The swappable transport — escrow-protocol payloads as kind-31337 Nostr events over the nGate relays. *(deploy-time; the inner schnorr sig is the trust gate, not the event.)* |
| `index.js` | Boot entrypoint — env config → open ledger → wire transport → `start()`. |
| `test/box.test.js` | The box proven **in isolation** (real ledger/settle/disburse, mock chain + broadcast). |

## Run the proof (offline, no key/funds/network)

```sh
npm install            # escrow-core sibling must be cloned next to this repo
npm test               # 26 passing — settle+conserve, the two hard gates, idempotency
                       # (in-process + restart), lying-only-resplits, forged-dropped,
                       # transient→pending→retry, probe-guarded no-double-pay,
                       # terminal failed receipts, completion-fires-once, single-payment
                       # settlements (paid DMs/invites), no-key→recover-exactly-once
                       # (Node 24: use  node --test test/*.test.js)
```

## Deploy

Runbook: **`walkthrough.wiki`** — patched/firewalled/key-only-SSH Alpine host, unprivileged user,
OpenRC service. **Live** at `escrow.v4call.com`, settling real TEST-token sessions for
`node.v4call.com` (which runs keyless, `ESCROW_MODE=box`). The remaining money gate is the owner
placing the **real** (non-TEST) escrow account's active key.
**Never install Claude / dev tooling on the money box** — the box stays minimal code doing one job;
SSH access for logs/deploys is fine (owner rule, clarified 2026-07-07).
