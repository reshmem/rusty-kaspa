## Domain + Network IDs (Igra ↔ Kaspa ↔ Hyperlane)

This doc is a **single source of truth** for how we currently use:
- Kaspa “network” (devnet/testnet/mainnet)
- Igra runtime “network mode” (`--network ...`)
- Iroh `network_id` (Igra transport namespace + Kaspa consensus params selection)
- Hyperlane `chainId` vs `domainId`
- Hyperlane message `origin` and `destination` domain IDs
- Hyperlane chain “names” and the Hyperlane registry concept (local vs remote)

**Non-goal:** Do not change or reinterpret `group_id` in this doc. `group_id` is the trust anchor for the signer set and must remain independent.

---

## 1) Hyperlane: `chainId` vs `domainId` (and `origin`/`destination`)

### `chainId` (chain-native ID)
- A chain’s native identifier in its own ecosystem.
- On EVM, `chainId` is the EIP-155 chain ID used for transaction signing / replay protection.
- Hyperlane uses `chainId` when it needs to talk to and sign transactions for an EVM chain.

### `domainId` (Hyperlane protocol ID)
- A Hyperlane **protocol-level** identifier for a chain/domain (u32).
- It is the value used inside Hyperlane messages and contracts:
  - `Mailbox.dispatch(destinationDomain, ...)`
  - `HyperlaneMessage.origin`
  - `HyperlaneMessage.destination`

### `origin` and `destination`
A Hyperlane message always contains a **pair** of domain IDs:
- `origin`: the domainId of the chain where the message was dispatched
- `destination`: the domainId of the chain that should process the message

Important:
- A single `domainId` identifies **one** chain/domain.
- The pair `(origin, destination)` is **not** a “single domain”; it’s two domainIds.

### Relationship between `chainId` and `domainId`
- Hyperlane often configures `domainId == chainId` for EVM chains, but it’s not required.
- On non-EVM chains there may be no concept of `chainId`, but Hyperlane still uses `domainId`.

---

## 1.1) Igra “domain ID” convention (`0x97B{suffix}`)

Separately from Hyperlane’s EVM conventions, we use a compact hex **Igra domain ID family**:

- Base prefix (high 12 bits): `0x97B`
- Low nibble (`suffix`) encodes the environment/network.

This is intended to give us stable, human-recognizable u32 IDs that:
- are easy to spot in logs (`0x97B*`)
- have a small reserved namespace for environments

### How `97B1` is derived from `"IGRA"`

We start from ASCII bytes of `"IGRA"` and subtract `0x10` from each byte:

- `'I'` (73) → `73 - 16 = 57` → ASCII `'9'`
- `'G'` (71) → `71 - 16 = 55` → ASCII `'7'`
- `'R'` (82) → `82 - 16 = 66` → ASCII `'B'`
- `'A'` (65) → `65 - 16 = 49` → ASCII `'1'`

So `"IGRA"` → `"97B1"`.

Then **we interpret the resulting string as hex digits**:
- `"97B1"` → `0x97B1`
- `"97BD"` → `0x97BD`
- `"97B4"` → `0x97B4`

If the surrounding code expects a `u32`, these are represented as:
- `0x000097B1`, `0x000097BD`, `0x000097B4`, ...

Important: this is **not** the same scheme as ASCII-tag u32s like `"KASM"`/`"KASD"` (which are big-endian ASCII bytes, e.g. `"KASD"` → `0x4B415344`).

### Environment suffix allocation

- `0x97B1` → mainnet
- `0x97BD` → devnet
- `0x97B2`, `0x97B3`, `0x97B4`, `0x97B5`, `0x97B6`, `0x97B7`, `0x97B9`, `0x97BA`, `0x97BB`, `0x97BC`, `0x97BF` → testnets
  - Current testnet in use: `97B4`

---

## 2) Hyperlane registry (local vs remote)

Hyperlane tools and agents need:
- chain metadata (RPC URLs, chainId, domainId, protocol, etc.)
- addresses of deployed Hyperlane core contracts (Mailbox, ValidatorAnnounce, MerkleTreeHook, etc.)

That data lives in a **registry**.

### Local registry
- Files on disk.
- Our devnet uses a local filesystem registry under:
  - `/tmp/igra_devnet/hyperlane/registry`
- Example:
  - `.../chains/<chain-name>/metadata.yaml`
  - `.../chains/<chain-name>/addresses.yaml`

### Remote registry
- Same data, hosted somewhere (e.g., a shared HTTP registry or published registry repo).
- Useful for multi-machine environments or production bootstrapping.

### Why naming matters
Registry entries are keyed by **chain name** (`chains/<name>/...`).
If we use multiple names for the same (chainId, domainId), humans and tooling will get confused.

---

## 3) Igra networking knobs

### A) Igra runtime network (`--network ...`)
This is the Igra process network mode flag, currently used in devnet orchestration as:
- `kaspa-threshold-service --network devnet`

This mode is intended for “environment rules” (e.g. security restrictions, non-prod behavior).

### B) Kaspa node network (`kaspad --devnet`)
This is the Kaspa node’s actual network:
- `kaspad --devnet` starts a Kaspa devnet node.
- Igra talks to it via gRPC (e.g. `grpc://127.0.0.1:16110`).

### C) Iroh `network_id` (Igra transport namespace)
`iroh.network_id` is a small `u8` used for:

1) **Iroh gossip namespace separation**
   - It is mixed into the Iroh gossip “topic” hash:
     - `topic = blake3("kaspa-sign/v1" || network_id || group_id)`
   - Meaning: changing `network_id` changes the gossip topic even if `group_id` stays the same.
   - So `network_id` is an intentional “transport network selector”.

2) **Selecting Kaspa consensus params inside Igra**
   - Some logic chooses Kaspa consensus params based on `network_id`:
     - `0 -> mainnet params`, `2 -> devnet params`, `3 -> simnet params`, otherwise testnet params.
   - This means it currently plays a dual role: transport namespace + consensus-params hint.

Current devnet reality (important):
- In our generated devnet config, `iroh.network_id = 0` even though Igra is started with `--network devnet`.
- This is why we treat `iroh.network_id` as an explicit knob, not something automatically derived (for now).

---

## 4) Current devnet mapping (precise)

### Kaspa (devnet)
- `kaspad`:
  - network: devnet (`--devnet`)
  - gRPC: `127.0.0.1:16110`
  - wRPC borsh/json: `127.0.0.1:17110` / `127.0.0.1:17111`

### Igra signers (devnet)
- Igra runtime mode:
  - `kaspa-threshold-service --network devnet`
- Kaspa node connection:
  - `--node-url grpc://127.0.0.1:16110`
- Signer RPC endpoints (used by Hyperlane relayers as “Kaspa RPC”):
  - signer-01: `http://127.0.0.1:8088`
  - signer-02: `http://127.0.0.1:8089`
  - signer-03: `http://127.0.0.1:8090`
- Iroh:
  - `group_id`: derived from signer set (do not change)
  - `network_id`: currently `0` in devnet configs

### Hyperlane origin (EVM Anvil)
- Anvil RPC: `http://127.0.0.1:8545`
- EVM `chainId`: `31337`
- Hyperlane `domainId` (origin): `31337`
- Hyperlane Rust agent chain name for domainId=31337:
  - `test4` (known domain name used by Hyperlane Rust agents)

### Hyperlane destination (Kaspa in our devnet)
- Hyperlane `domainId` (destination): currently `7`
- Hyperlane Rust agent chain name:
  - `kaspa`
- Hyperlane relayer uses Igra signer RPC URLs for “kaspa” RPC and uses the Igra `group_id` as the “mailbox/igp/va/mth” fields for the Kaspa adapter.

---

## 5) Current mismatch / confusion points

### A) Igra Hyperlane “domain” is keyed by **origin**, but is documented as “destination”
Security model:
- The destination verifier chooses a validator set based on the **origin** domain (common model: destination policy keyed by origin).

Current Igra implementation:
- Validator set lookup for `hyperlane.mailbox_process` is done by `message.origin`.
- Proof verification is keyed by `message.origin`.

But config comment currently says `HyperlaneDomainConfig.domain` is “Destination domain”.
This is misleading and can cause misconfiguration.

### B) Devnet destination domainId = `7` is arbitrary
`7` is not self-describing.
It doesn’t correspond to:
- Kaspa network IDs
- Hyperlane’s chainId
- or a stable “Kaspa devnet domain” tag

### C) Hyperlane chain name aliasing (`anvil1` vs `test4`)
In our devnet today:
- The Hyperlane CLI registry entry is seeded under the name `anvil1`
- Hyperlane Rust agents use the name `test4` for the same `domainId=31337`

These refer to the same origin chain, but different names increase confusion.

---

## 6) Alignment proposal (no changes in this doc)

### 1) Clarify Igra Hyperlane domain semantics (origin-keyed)
Make it explicit in docs and code wording that:
- `[[hyperlane.domains]]` is the destination policy table keyed by **origin domainId**
- Igra selects validator sets by `message.origin`

Concrete changes to consider later:
- update config comments/names
- update RPC error strings/logs that incorrectly say “destination domain” when it’s an origin-keyed lookup

### 2) Replace devnet `7` with a canonical Kaspa Hyperlane domainId
Use a self-describing u32 domainId for Kaspa, aligned across environments:
- devnet: `"KASD"` (`0x4B41_5344`)
- testnet: `"KAST"` (`0x4B41_5354`)
- mainnet: `"KASM"` (`0x4B41_534D`)

Then use the chosen value consistently across:
- EVM dispatch `destinationDomain`
- Hyperlane Rust relayer config “kaspa” chain `domainId`
- fake-hyperlane env/config paths

### 3) Make Hyperlane origin chain naming consistent (configs only)
Do **not** change upstream Hyperlane behavior.
Instead, align our devnet registry + agent configs so the same chain isn’t called two names.

Options:
- Prefer `test4` everywhere for the origin chain in devnet (registry + agents), or
- Keep an explicit alias (duplicate registry entry) and document it clearly.

---

## 7) Future multi-destination note
Today our destination is “Kaspa/Igra”.
When we support multiple destinations, the security model becomes:
- Destination defines policy **per origin**:
  - `(destination, origin) -> validator_set + threshold + mode`

For now (single destination), storing “origin -> validator set” is the simplest correct representation.
