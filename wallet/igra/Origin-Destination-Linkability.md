# Origin ↔ Destination Linkability (Hyperlane EVM → Kaspa via Igra)

This document explains how an external observer can correlate (“link”) origin-side Hyperlane messages on an EVM chain to destination-side Kaspa transactions, both:

1) **without any special on-chain linking**, using public data + heuristics, and  
2) **with explicit linking**, by embedding an origin identifier inside the Kaspa transaction (recommended for monitoring).

---

## 1. Definitions

- **Confidentiality**: whether third parties can learn message contents (recipient/amount).
- **Linkability**: whether third parties can reliably correlate:
  - an origin `Dispatch` (and its `message_id`, `sender`)  
  - to the corresponding destination Kaspa transaction (`tx_id`).

In our current system, confidentiality is already low:

- EVM `Mailbox.dispatch` emits public logs and carries the message body.
- Kaspa transactions publicly reveal outputs (recipient script / amount).

The remaining question is linkability: how easy it is to prove *which* origin message produced *which* Kaspa transaction.

---

## 2. What’s publicly visible today (no protocol changes)

### 2.1 Origin chain (EVM)

From EVM logs and state, an observer can obtain:

- `message_id` (unique per message)
- `sender` (bytes32 / address-derivable depending on origin app)
- `destination_domain`
- `body` (in our encoding: `amount_sompi_u64_le || kaspa_address_utf8`)
- `dispatch_tx_hash`, block number, block timestamp

So the observer knows `(kaspa_address, amount)` for each message, plus a time window.

### 2.2 Destination chain (Kaspa)

From Kaspa chain data, an observer can obtain:

- output(s) paying the destination address (script) and amount
- `tx_id`
- inclusion/confirmation metrics (DAA score / blue score)

So the observer can detect that “a transfer to `kaspadev:...` for `X` sompi occurred”.

### 2.3 Igra as a public correlation oracle (if reachable)

If an observer can query a running `igra-service`, linkability becomes trivial because Igra indexes:

- `message_id → delivered?`
- `message_id → tx_id` (delivery record)
- message fields in the indexer records (sender/recipient/origin/destination/nonce/body)

In that case, the observer does not need heuristics at all; it just queries Igra’s indexer endpoints.

---

## 3. How an external observer links origin ↔ destination today (without embedding IDs)

### 3.1 Easy case: Igra endpoints are accessible

If any destination node exposes the Hyperlane/Igra read endpoints, the observer links directly:

- read EVM `message_id` from origin logs,
- query destination `delivered(message_id)` and/or deliveries index,
- obtain `tx_id`.

This is “perfect linkability” if Igra is reachable.

### 3.2 No Igra access: link via public data + time window

Even without Igra access, an observer can link with high confidence in many cases by:

1) Watching EVM `Dispatch` logs to obtain `(kaspa_address, amount, dispatch_time)`.
2) Scanning Kaspa blocks/mempool around `dispatch_time ± Δ` for transactions paying:
   - the same destination address/script, and
   - the same amount.

This often works in devnets and low-volume environments because collisions are rare.

### 3.3 Ambiguity cases (where linkability is weaker)

Linking via `(destination, amount, time)` becomes ambiguous when:

- many messages pay the **same** destination address and **same** amount (common if using a single “miner address”),
- there are retries/resubmissions causing multiple candidate transactions in the same window,
- multiple unrelated systems pay the same destination/amount.

In these cases, “which origin message produced which tx” may not be uniquely provable without an extra identifier.

---

## 4. Explicit on-chain linking: include origin identifiers in Kaspa tx payload

Kaspa native transactions have a `payload: Vec<u8>` field that participates in the signing hash when non-empty. This makes it a natural place to embed stable origin identifiers.

### 4.1 What to embed

Recommended minimal set:

- `message_id` (32 bytes, globally unique for Hyperlane)
- `sender` (32 bytes, as observed in the Hyperlane message)

Optionally:

- `event_id` (32 bytes), if you want explicit linkage to Igra’s internal event model

In practice, `message_id` alone is sufficient for unique linking; `sender` helps with attribution and debugging.

### 4.2 How it works

- During proposal/PSKT construction, all signers deterministically compute the same payload bytes from the canonical event/signing material.
- The payload bytes become part of the unsigned transaction skeleton.
- All partial signatures are over that exact payload (so the final tx commits to the identifiers).
- Any external observer can then:
  - read `tx.payload`,
  - parse out `message_id`/`sender`,
  - link to the exact origin `Dispatch` by `message_id`.

### 4.3 Deterministic encoding (avoid future footguns)

Use a stable, versioned, binary encoding (avoid JSON):

```
payload :=
  "igra:link:v1" (ASCII) ||
  origin_domain_u32_le ||
  message_id[32] ||
  sender[32] ||
  event_id[32]   # optional (either always present or omitted by version)
```

Rules:

- version tag must change on breaking format changes
- fixed-endianness and fixed-length fields
- for non-Hyperlane sources, define `sender = 0x00..00` (or use a different version/tag)

### 4.4 Tradeoffs

Pros:

- makes origin↔destination correlation **cryptographically explicit**
- enables trust-minimized monitoring and forensics
- simplifies incident response (“which message caused this payout?”)

Cons:

- increases compute mass slightly (payload size affects fee)
- increases linkability by design (even if destination/amount were already public)
- is chain-specific (Bitcoin has no native tx payload; you’d need an `OP_RETURN` strategy there)

---

## 5. Monitoring approach with and without payload linking

### 5.1 Without embedding IDs

Monitoring can still be strong, but typically relies on at least one of:

- querying Igra indexer endpoints, or
- running an observer that watches both chains and correlates via `(destination, amount, time)`, accepting ambiguity in edge cases.

### 5.2 With embedding IDs (recommended for production observability)

An observer can be fully trust-minimized:

- origin: read `message_id` from EVM `Dispatch`
- destination: read `message_id` from Kaspa tx `payload`
- correlate 1:1 without relying on Igra’s internal DB/logs

This also supports independent audits where the observer is operated by a third party.

---

## 6. Summary

- We already have low confidentiality (destination/amount are public on both chains).
- The real design choice is **how much linkability we want**:
  - today: linkability is easy if Igra endpoints are accessible, otherwise heuristic and sometimes ambiguous
  - with payload linking: linkability is deterministic, cryptographic, and observer-friendly

