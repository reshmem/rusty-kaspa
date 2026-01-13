# Hyperlane v3 Relayer/Validator Interaction (Kaspa Threshold Signing Context)

This note captures how Hyperlane v3 validators, relayers, and contracts interact for message attestation and delivery, and how that maps to the kaspa-threshold-signing service expectations.

## Message and ID
- Origin chain Mailbox emits `HyperlaneMessage` leaves into its Merkle tree.
- `HyperlaneMessage` fields (serialized in order, big-endian ints): `version (u8) | nonce (u32) | origin (u32) | sender (H256) | destination (u32) | recipient (H256) | body (bytes)`.
- `message_id = keccak256(serialized_message_bytes)`. This 32-byte value is the Merkle leaf.

## Origin Merkle Tree
- Managed on the **origin** chain by the MerkleTreeHook/Mailbox contract.
- Right-sparse incremental Merkle tree, fixed `TREE_DEPTH = 32` (capacity 2^32 leaves).
- Leaf insertion event: `MerkleTreeInsertion { leaf_index: u32, message_id: H256 }`.
- Proof: `(leaf=message_id, index, path[32] of sibling hashes)`.
- Root updates monotonically as leaves append; zero hashes pad empties.

## Checkpoints
- A checkpoint binds an origin root/index (+ sometimes message_id):
  - `Checkpoint { merkle_tree_hook_address, mailbox_domain, root, index }`
  - `CheckpointWithMessageId { checkpoint: Checkpoint, message_id }`
- Validators sign `CheckpointWithMessageId` using EIP-191 over `signing_hash = keccak256(domain_hash(merkle_tree_hook_address, mailbox_domain) || root || index_be || message_id)`.
- Signatures are secp256k1 ECDSA (65 bytes, recoverable).

## Validator Responsibilities
- Run origin-chain observer + publish checkpoints:
  - Track the origin Merkle tree, produce checkpoints, sign them.
  - Host signed checkpoints at announced storage locations (e.g., S3/HTTPS).
- Announce storage location on **origin** via ValidatorAnnounce contract:
  - Signed `Announcement { validator, mailbox_address, mailbox_domain, storage_location }`.
  - Relayer fetches storage locations from this contract for the validators required by the destination ISM.

## Destination ISM (source of truth)
- The validator set + threshold that matter live on the **destination** chain in the ISM contract.
- Relayer calls `validators_and_threshold(message)` on the destination ISM to learn the active set/threshold.
- If the destination ISM set/threshold disagree with who actually signs on origin, delivery fails; the ISM view is authoritative.

## Relayer Responsibilities
- For each origin→destination message:
  1) Query destination ISM for `(validators[], threshold)`.
  2) Fetch validator storage locations from origin ValidatorAnnounce for those validators.
  3) Download signed checkpoints, verify EIP-191 signatures against the ISM validator addresses, and assemble a quorum (`threshold`) over a consistent checkpoint.
  4) Build metadata for `Mailbox.process` on the **destination** chain:
     - **MessageIdMultisig ISM** (no per-message proof):
       - `CheckpointMerkleTreeHook` (origin address, 32 bytes)
       - `CheckpointMerkleRoot` (origin root, 32 bytes)
       - `CheckpointIndex` (origin index, u32 BE)
       - `Signatures` (concat of `threshold` 65-byte sigs, validator order)
     - **MerkleRootMultisig ISM** (with per-message proof):
       - `CheckpointMerkleTreeHook` (origin address)
       - `MessageMerkleLeafIndex` (u32 BE)
       - `MessageId` (32 bytes)
       - `MerkleProof` (ABI-encoded array of 32-byte siblings; depth 32 typical)
       - `CheckpointIndex` (u32 BE)
       - `Signatures` (concat of `threshold` sigs)
  5) Submit `Mailbox.process(message, metadata)` on the **destination** chain (optionally batched).
- The relayer never pulls validator set/threshold from the origin chain; it only trusts the destination ISM for that.

## Verification Flow on Destination
- Mailbox.process calls the destination ISM:
  - Re-fetches/uses its own validator set/threshold (source of truth).
  - Verifies signatures over the checkpoint (recover == validator, count >= threshold).
  - For MerkleRootMultisig: verifies Merkle proof of `message_id` against `root/index`.
  - For MessageIdMultisig: checkpoint already binds `message_id` at `index`, so no per-message proof.
- If all checks pass, the message is considered proven and the recipient executes.

## Why signatures and proofs matter
- Destination chain must independently verify origin inclusion and validator attestation; relayer is untrusted.
- Validator signatures attest to the origin root/index (and message_id for MessageIdMultisig).
- Merkle proof (MerkleRootMultisig) ties the specific message to that root when needed.

## Calldata size (empty message, 20 sigs, depth 32)
- MessageIdMultisig: ~1.7 KB calldata (~27k gas for calldata on EVM).
- MerkleRootMultisig: ~2.7 KB calldata (~44k gas for calldata), larger due to 32-sibling proof.
- Add message body padding if non-empty.

## Operational alignment
- Validator set/threshold must be kept in sync (operationally/governance) between who signs on origin and what the destination ISM expects; otherwise verification fails.
- Relayer follows the destination ISM view; the ISM must be updated to reflect validator rotations.***
