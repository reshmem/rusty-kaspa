# Frequently Asked Questions

**Last Updated:** 2026-02-05

---

## General Questions

### What is Igra?

Igra is a **leaderless threshold signature coordination system** for UTXO blockchains. It helps multiple independent signers safely coordinate to produce threshold-signed transactions without requiring a trusted coordinator or leader.

**In simpler terms:** It's the "traffic controller" that ensures multiple parties can jointly sign blockchain transactions without conflicts.

---

### Why is it called "Igra"?

The name comes from the Serbo-Croatian word "игра" (igra), meaning "game" or "play," reflecting the protocol's game-theoretic coordination mechanisms.

---

### What blockchains does Igra support?

**Currently supported:**
- ✅ Kaspa (production-ready)

**Planned:**
- ⏳ Bitcoin (requires PSBT adapter)
- ⏳ Litecoin (requires PSBT adapter)
- ⏳ Any UTXO-based blockchain with transaction templates

---

### Is Igra production-ready?

**Status: Pre-release (v0.1.0)**

- ✅ Core protocol implemented and tested
- ✅ Deployed on Kaspa testnet
- ⏳ Security audit pending
- ⏳ Mainnet deployment pending audit completion

**Recommendation:** Use for testing and development. Production use should wait for security audit and mainnet release.

---

## Technical Questions

### How is Igra different from MuSig2 or FROST?

**Igra** = **Coordination** layer (decides which transaction to sign)
**MuSig2/FROST** = **Cryptographic** layer (how to generate threshold signatures)

They solve different problems and are complementary:
- **Igra:** "Should we sign transaction A or transaction B?"
- **MuSig2/FROST:** "How do we generate a threshold signature for transaction A?"

**Current state:** Igra uses independent per-input Schnorr signatures. Future versions may integrate MuSig2 or FROST for signature aggregation.

---

### Does Igra require a leader?

**No.** That's the key innovation. All signers participate equally:
- Everyone proposes templates simultaneously
- Quorum voting determines the winner
- No single coordinator or leader election

**Benefits:**
- No single point of failure
- Faster (no election overhead)
- More decentralized

---

### What happens if signers see different UTXOs?

This is the core problem Igra solves. When signers observe different UTXO sets:

1. Each signer builds a template from their view
2. Signers vote on template hashes
3. Majority quorum (>50%) determines the winner
4. All signers commit to the winning template
5. Only then do they sign

**Result:** Safe convergence even under divergence

---

### What if quorum is never reached?

The protocol has explicit timeout and retry logic:

```
Round 0: Try template with UTXO ordering #1
   ↓ (timeout after 5 seconds)
Round 1: Try template with UTXO ordering #2
   ↓ (timeout after 5 seconds)
Round 2: Try template with UTXO ordering #3
   ↓ (timeout after 5 seconds)
...
After max retries (default: 10): Mark event as ABANDONED
```

**Safety guarantee:** If quorum is never reached, the event is explicitly abandoned. No accidental double-signing.

---

### How does Igra handle Byzantine (malicious) signers?

**Short answer:** Current version assumes honest majority (crash-fault tolerance). Full Byzantine fault tolerance is planned for future releases.

**Current guarantees:**
- ✅ Safety under crash failures
- ✅ Safety under network partitions
- ✅ Safety under message delays
- ❌ No protection against intentional equivocation

**Why this is acceptable:** Threshold signatures already assume at least `m` honest signers. Igra adds coordination without weakening that assumption.

**Future work:** BFT extension requires signed lock certificates and explicit slashing.

---

### What is a CRDT and why use it?

**CRDT** = Conflict-Free Replicated Data Type

It's a data structure that can be updated independently by multiple parties and automatically merged without conflicts.

**Why use it for signatures:**
- Signatures are **order-independent** (Sig1 + Sig2 = Sig2 + Sig1)
- No additional coordination needed after template agreement
- Handles message delays and reordering gracefully
- Simple and efficient (just set union)

**Alternative:** Running another consensus round for each signature would be much slower.

---

## Operational Questions

### How many signers do I need?

**Minimum:** 3 signers with 2-of-3 threshold
**Recommended:** 5-7 signers with 3-of-5 or 4-of-7 threshold

**Trade-offs:**
- **More signers:** Higher fault tolerance, more decentralization, slower
- **Fewer signers:** Faster, simpler, less fault tolerance

**Quorum requirement:** Must be >50%
```
N=3 → quorum=2
N=5 → quorum=3
N=7 → quorum=4
N=9 → quorum=5
```

---

### What are the hardware requirements?

**Per signer node:**
- **CPU:** 2 cores minimum, 4 cores recommended
- **RAM:** 4 GB minimum, 8 GB recommended
- **Disk:** 10 GB (SSD recommended for RocksDB)
- **Network:** 1 Mbps sustained, 10 Mbps burst

**Kaspa node requirements** (separate):
- **CPU:** 4 cores
- **RAM:** 8 GB
- **Disk:** 50 GB (for full node with UTXO index)

See [Infrastructure Requirements](../devops/infrastructure/01-requirements.md) for details.

---

### How do I monitor Igra nodes?

Igra exposes Prometheus metrics on `/metrics` endpoint:

**Key metrics:**
- `igra_events_total` - Total events processed
- `igra_events_completed` - Successfully completed events
- `igra_events_abandoned` - Failed/abandoned events
- `igra_proposal_rounds` - Number of proposal rounds per event
- `igra_signature_threshold_time` - Time to reach signature threshold

See [Monitoring Guide](../operators/monitoring/01-monitoring-overview.md) for complete list.

---

### Can I run Igra on a single machine for testing?

**Yes!** See [Devnet Quickstart](../operators/deployment/01-quickstart-devnet.md) for running 3 nodes locally.

**Use cases:**
- Development and testing
- Integration testing
- Reproducing issues

**Not for production:** Production should use geographically distributed nodes.

---

## Security Questions

### How are signing keys managed?

**Key generation:**
- BIP39 mnemonic (12-24 words)
- BIP32 hierarchical deterministic derivation
- Schnorr-compatible key extraction

**Key storage:**
- Encrypted with XChaCha20Poly1305
- Encryption key from environment variable (`WALLET_SECRET`)
- Keys exist in memory only during signing
- Memory zeroed after use (Rust `Zeroize` trait)

**Limitations:**
- ❌ No HSM support (keys in process memory)
- ❌ No hardware security module integration

See [Key Management](../devops/security/02-key-management.md) for details.

---

### Can encryption keys be rotated?

**Yes.** See [Passphrase Rotation Guide](../devops/security/03-passphrase-rotation.md).

**Process:**
1. Decrypt mnemonic with old key
2. Re-encrypt with new key
3. Update environment variable
4. Restart node

**Zero downtime rotation:** Use blue-green deployment or rolling restarts.

---

### What if a signing key is compromised?

**Threshold property provides defense-in-depth:**
- With m-of-n threshold, attacker needs **m** compromised keys to forge signatures
- Single key compromise does not break the system

**Response procedure:**
1. **Immediate:** Shut down compromised node
2. **Generate** new key for that signer position
3. **Update** multisig address with new public key
4. **Migrate** funds to new multisig address
5. **Investigate** how compromise occurred

**Prevention:** See [Security Best Practices](../devops/security/01-security-overview.md)

---

### How are cross-chain events authenticated?

Igra validates events using **external validator signatures:**

**Hyperlane (m-of-n):**
- Configure M validator public keys (ECDSA secp256k1)
- Require ≥T signatures (threshold)
- Each validator independently signs message ID
- Rejection if <T valid signatures

**LayerZero (single endpoint):**
- Configure endpoint public key (ECDSA secp256k1)
- Require exactly 1 valid signature
- Rejection if signature verification fails

**Trust model:** Igra trusts the external validator set. This trust is inherited from the cross-chain messaging protocol (e.g., Hyperlane's economic security via staked validators).

---

## Integration Questions

### How do I submit an event to Igra?

**Via REST API:**

```bash
curl -X POST http://localhost:8001/api/v1/events \
  -H "Content-Type: application/json" \
  -d '{
    "external_id": "0x1234...",
    "source": {
      "type": "hyperlane",
      "origin_domain": 1
    },
    "destination": "kaspa:qr0...",
    "amount_sompi": 100000000000,
    "validator_signatures": [...],
    "reason": "Bridge withdrawal"
  }'
```

**Response:**
```json
{
  "event_id": "a1b2c3...",
  "status": "proposing"
}
```

See [REST API Documentation](../developers/api/02-rest-api.md) for complete reference.

---

### How do I check event status?

**Query by event ID:**

```bash
curl http://localhost:8001/api/v1/events/{event_id}
```

**Response:**
```json
{
  "event_id": "a1b2c3...",
  "phase": "completed",
  "round": 0,
  "tx_id": "def456...",
  "created_at": "2026-02-05T12:34:56Z",
  "completed_at": "2026-02-05T12:35:01Z"
}
```

**Possible phases:**
- `unknown` - Not yet processed
- `proposing` - Building templates, voting
- `committed` - Template agreed, signing in progress
- `completed` - Transaction submitted and confirmed
- `failed` - Temporary failure, will retry
- `abandoned` - Permanent failure after max retries

---

### Can I run Igra with custom event sources?

**Yes.** Igra supports multiple source types:

```rust
enum SourceType {
    Hyperlane { origin_domain: u32 },
    LayerZero { src_eid: u32 },
    Api,      // Manual API submission
    Manual,   // Operator-triggered
    // Add custom source types here
}
```

**To add custom source:**
1. Add variant to `SourceType` enum
2. Implement signature verification in `domain/validation/`
3. Configure validator public keys
4. Submit events with custom source type

See [Developer Guide](../developers/architecture/06-codebase-structure.md) for details.

---

## Troubleshooting Questions

### Why is my event stuck in "proposing" phase?

**Common causes:**

1. **Insufficient signers online**
   - Need ≥quorum signers to reach consensus
   - Check if all nodes are running and connected

2. **UTXO divergence**
   - Signers seeing very different UTXO sets
   - Check blockchain node synchronization
   - Verify all signers connect to synced nodes

3. **Network partition**
   - Signers cannot communicate via gossip
   - Check firewall rules and network connectivity
   - Verify bootstrap nodes configured correctly

4. **Insufficient funds**
   - Multisig balance too low for requested amount + fees
   - Check balance with `kaspa-cli getbalance`

See [Troubleshooting Guide](../operators/troubleshooting/01-common-issues.md)

---

### Why do some events take longer than others?

**Factors affecting latency:**

1. **UTXO convergence**
   - First round: All signers see same UTXOs → Fast (1-2 sec)
   - Multiple retries: Different UTXO views → Slow (10-30 sec)

2. **Network conditions**
   - Good connectivity → Fast proposal propagation
   - Slow network → Delayed message delivery

3. **Concurrent events**
   - Sequential events → No UTXO contention
   - Concurrent events → May compete for same UTXOs, requiring retries

4. **Node performance**
   - Fast nodes → Quick template building
   - Slow nodes → Delayed proposals

---

### How do I debug a failed event?

**Step-by-step debugging:**

1. **Check event status**
   ```bash
   curl http://localhost:8001/api/v1/events/{event_id}
   ```

2. **Check node logs**
   ```bash
   grep {event_id} /var/log/igra/igra-service.log
   ```

3. **Common error patterns:**
   - `InsufficientUTXOs` → Fund the multisig
   - `QuorumNotReached` → Check signer connectivity
   - `ValidationFailed` → Check validator signatures
   - `PolicyViolation` → Check amount limits/whitelist

4. **Check blockchain state**
   ```bash
   kaspa-cli getutxos {multisig_address}
   ```

See [Debugging Guide](../operators/troubleshooting/02-debugging-guide.md)

---

## Performance Questions

### What is the maximum throughput?

**Theoretical limits:**
- **Sequential events:** 2-5 events/sec (limited by blockchain confirmation)
- **Concurrent events:** 10-50 events/sec (limited by UTXO pool size)

**Real-world performance:**
- **Testnet observed:** 5-15 events/min with occasional retries
- **Optimal conditions:** 20-30 events/min

**Bottlenecks:**
1. Blockchain confirmation time (Kaspa: 10 seconds for 10 blocks)
2. UTXO availability (concurrent events compete)
3. Network propagation (gossip latency)

---

### Can Igra scale to 100+ signers?

**Current limitations:**
- Message complexity: O(N²) per round
- With N=100, each round = 10,000 messages
- Gossip bandwidth and CPU become bottlenecks

**Practical limits:**
- ✅ 3-7 signers: Excellent performance
- ✅ 10-20 signers: Good performance
- ⚠️ 50+ signers: Degraded performance
- ❌ 100+ signers: Not recommended

**Future optimizations:**
- Hierarchical quorum (multiple layers)
- Signature aggregation (MuSig2)
- Optimized gossip (merkle trees, bloom filters)

---

## Contributing Questions

### How can I contribute to Igra?

**Ways to contribute:**
1. **Code:** Submit PRs for bug fixes or features
2. **Documentation:** Improve or translate docs
3. **Testing:** Report bugs, test on different platforms
4. **Community:** Help others in Discord

See [Contributing Guide](../developers/contributing/04-pull-request-process.md)

---

### Where is the source code?

**Repository:** https://github.com/kaspanet/rusty-kaspa

**Location:** `wallet/igra/`

**Components:**
- `igra-core/` - Core protocol implementation
- `igra-service/` - Service layer and API
- `docs2/` - This documentation

---

### Is there a roadmap?

**Current status:** Pre-release (v0.1.0)

**Near-term (Q1-Q2 2026):**
- [ ] Security audit
- [ ] Mainnet deployment
- [ ] UTXO consolidation feature
- [ ] Enhanced monitoring

**Mid-term (Q3-Q4 2026):**
- [ ] Bitcoin support
- [ ] MuSig2 integration
- [ ] Byzantine fault tolerance

**Long-term (2027+):**
- [ ] Hardware security module (HSM) support
- [ ] Multi-chain abstraction layer
- [ ] Performance optimizations for 50+ signers

See [Future Enhancements](../developers/design/03-future-enhancements.md)

---

## Still Have Questions?

### Documentation
- Browse complete docs: [Documentation Index](../README.md)

### Community Support
- **Discord:** [Kaspa Discord](https://discord.gg/kaspa) → `#igra-support` channel
- **GitHub Issues:** [File a question](https://github.com/kaspanet/rusty-kaspa/issues)

### Security Issues
- **Email:** security@kaspa.org (do not file public issues)
- **PGP Key:** Available on kaspa.org

---

**Last Updated:** 2026-02-05
