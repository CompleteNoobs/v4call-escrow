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
npm test               # 10 passing — settle+conserve, the two hard gates, idempotency
                       # (in-process + restart), lying-only-resplits, forged-dropped,
                       # transient→retry, no-key→recover-exactly-once
```

## Deploy (gated)

Standing up the real box on its own minimal Alpine host with a real Hive account + the real money
key, and the **live TEST-token dry-run** before any production node points at it, are **owner-gated**
— see the deploy runbook (`walkthrough.wiki`, forthcoming) and handover-escrow-core §8.
**No Claude / no dev tooling on the money box** — operate via logs + `docker exec`.

The node-side flip (node → keyless reporter that publishes `event-report`s and consumes
`settlement-receipt`s) is the **separate next increment** (handover-escrow-core §6 territory; the
in-process seam already exists in `v4call-node`).
