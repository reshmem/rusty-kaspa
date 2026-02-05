# Use Cases

**Last Updated:** 2026-02-05

This document describes real-world scenarios where Igra provides value.

---

## 1. Cross-Chain Asset Bridges

### Scenario
A decentralized bridge connects Ethereum and Kaspa, allowing users to transfer assets between chains.

### Problem Without Igra
- 7 validators must coordinate to sign withdrawal transactions on Kaspa
- Validators observe different UTXO sets due to network delays
- Some validators build templates using UTXO A, others use UTXO B
- Signatures fragment → withdrawal fails
- User funds stuck in bridge

### Solution With Igra
```
1. User locks 100 ETH on Ethereum
2. Hyperlane validators attest to the lock event
3. Igra signers receive attested event
4. Two-phase protocol: Signers vote on transaction template
5. Quorum reached: All signers commit to same template
6. CRDT collection: Signatures merged until threshold
7. Transaction submitted: User receives 100 WKAS on Kaspa
```

### Benefits
- ✅ **Safe withdrawals**: No risk of double-spending locked funds
- ✅ **Decentralized**: No single bridge operator controls funds
- ✅ **Fault-tolerant**: Works even if some validators are offline
- ✅ **Fast finality**: Kaspa's 1-second blocks + efficient coordination

### Example Deployment
- **Ethereum → Kaspa bridge** (production)
- 9 validators with 6-of-9 threshold
- Average withdrawal time: 10-30 seconds
- Handles UTXO divergence gracefully via retries

---

## 2. Corporate Treasury Management

### Scenario
A company holds 1,000,000 KAS in a multisig wallet. Large payments require approval from 5-of-7 executives.

### Problem Without Igra
- Executives each run threshold signing software independently
- No coordination when UTXO sets diverge
- Manual intervention required for every payment
- High operational overhead and error risk

### Solution With Igra
```
1. CFO submits payment request via API
2. Request validated against policy (amount limits, whitelist)
3. Igra coordinates signing across 7 executive nodes
4. 5 executives' signatures collected automatically
5. Transaction submitted to blockchain
6. Payment completed, audit log recorded
```

### Benefits
- ✅ **Automated coordination**: No manual template sharing
- ✅ **Policy enforcement**: Amount limits, destination whitelist, daily velocity
- ✅ **Audit trail**: All events logged with timestamps and approval records
- ✅ **Business continuity**: Up to 2 executives can be unavailable

### Example Policy Configuration
```toml
[policy]
min_amount_sompi = 10_000_000_000      # 100 KAS minimum
max_amount_sompi = 100_000_000_000_000 # 1M KAS maximum
max_daily_volume_sompi = 500_000_000_000_000 # 5M KAS/day
allowed_destinations = [
  "kaspa:qr0vendor1address...",
  "kaspa:qr0vendor2address...",
]
require_reason = true
```

---

## 3. Decentralized Exchange Settlement

### Scenario
A DEX on Kaspa uses threshold-signed vaults for custody. Trades are settled by moving UTXOs between vault addresses.

### Problem Without Igra
- High-frequency trades require many coordinated signatures
- UTXO contention: Multiple trades competing for same UTXOs
- Leader-based coordination creates bottleneck
- Single point of failure during settlement

### Solution With Igra
```
1. User submits trade order
2. DEX matching engine finds counterparty
3. Settlement event generated
4. Igra coordinates vault signers
5. Trade executed atomically
```

### Benefits
- ✅ **High throughput**: Leaderless coordination scales better
- ✅ **Parallel settlement**: Multiple trades processed concurrently
- ✅ **UTXO management**: Deterministic selection avoids conflicts
- ✅ **No MEV**: Settlement order determined by consensus, not single leader

---

## 4. Decentralized Stablecoin Issuance

### Scenario
A decentralized stablecoin issues tokens on Kaspa, backed by BTC held in a threshold-signed vault.

### Problem Without Igra
- Mint/burn operations require coordinating 11-of-15 signers
- Different signers may observe different collateral states
- Byzantine actors could attempt to double-spend collateral
- Trust assumptions around coordinator

### Solution With Igra
```
1. User deposits BTC collateral via proof system
2. Oracle validators attest to collateral deposit
3. Igra signers coordinate to mint stablecoins
4. User receives stablecoins on Kaspa
5. Redemption: Burn stablecoins → Igra coordinates BTC release
```

### Benefits
- ✅ **Verifiable minting**: All signers agree on same collateral state
- ✅ **Decentralized governance**: No single entity controls minting
- ✅ **Byzantine resistance**: Quorum prevents minority double-spend attempts
- ✅ **Auditability**: All mint/burn events recorded with full trail

---

## 5. Multi-Jurisdiction Compliance

### Scenario
A financial service provider must comply with regulations in multiple jurisdictions. Payments require approval from compliance officers in each region.

### Problem Without Igra
- 3 compliance officers (US, EU, Asia) must approve large transfers
- Each officer uses different infrastructure and blockchain nodes
- Manual coordination via email/phone
- Slow, error-prone, no audit trail

### Solution With Igra
```
1. Payment request submitted to compliance system
2. Request routed to 3 regional compliance nodes
3. Each officer reviews and approves via dashboard
4. Igra coordinates signatures across regions
5. Transaction executed once 3-of-3 approved
6. Compliance audit log generated
```

### Benefits
- ✅ **Global coordination**: Works across time zones and networks
- ✅ **Compliance enforcement**: Policy rules enforced automatically
- ✅ **Regulatory audit**: Complete trail of approvals and rejections
- ✅ **Fault tolerance**: Handles network issues between regions

---

## 6. DAO Treasury Operations

### Scenario
A DAO holds 10M KAS in treasury. Spending proposals require 7-of-12 council member approval.

### Problem Without Igra
- Council members vote on proposals but signing is separate manual process
- No automated connection between governance vote and transaction execution
- Centralized multisig coordinator creates trust assumptions
- Slow execution after vote passes

### Solution With Igra
```
1. DAO proposal passes on-chain governance
2. Proposal result triggers Igra event via oracle
3. Council nodes automatically attempt signing
4. 7-of-12 signatures collected via CRDT
5. Treasury transaction executed
6. On-chain proof of execution published
```

### Benefits
- ✅ **Trustless execution**: No coordinator controls funds
- ✅ **Automated workflow**: Vote → Sign → Execute (no manual steps)
- ✅ **Censorship resistance**: Any 7 council members can execute
- ✅ **Transparent**: All operations visible on-chain

---

## 7. Institutional Custody

### Scenario
A crypto custody provider manages client assets in threshold-signed vaults. Multiple internal approvers required for withdrawals.

### Problem Without Igra
- Each client has unique approval workflow (2-of-3, 4-of-7, etc.)
- Custom integration required for each blockchain
- Leader-based architecture creates single point of failure
- Difficult to achieve high availability SLAs

### Solution With Igra
```
1. Client submits withdrawal via API
2. Internal approval workflow triggered
3. Required approvers review and sign via HSM
4. Igra coordinates signatures across approval nodes
5. Withdrawal executed to client address
6. Confirmation sent to client
```

### Benefits
- ✅ **Multi-chain support**: Same coordination logic for Kaspa, Bitcoin, etc.
- ✅ **Flexible policies**: Per-client approval requirements
- ✅ **High availability**: Leaderless design eliminates single point of failure
- ✅ **Audit & compliance**: Complete records for regulatory reporting

---

## 8. Decentralized Mixer (Privacy Protocol)

### Scenario
A privacy protocol coordinates threshold signatures to mix UTXOs, breaking on-chain linkability.

### Problem Without Igra
- Mixing rounds require all participants to sign simultaneously
- Participants may observe different UTXO states
- One malicious participant can abort the mix
- Centralized coordinator knows participant linkages

### Solution With Igra
```
1. Participants register UTXOs for mixing
2. Igra coordinates mixing transaction across participants
3. Two-phase ensures all participants agree on same mix
4. Signatures collected without revealing participant mapping
5. Mixed transaction submitted
```

### Benefits
- ✅ **Coordination without trust**: No single party controls mix
- ✅ **Fault tolerance**: Mix completes even if some participants drop
- ✅ **Privacy preserving**: CRDT collection doesn't reveal linkages
- ✅ **DoS resistance**: Quorum prevents single-party abort

---

## Comparison Matrix

| Use Case | Threshold | Frequency | Latency Requirement | Complexity |
|----------|-----------|-----------|---------------------|------------|
| Bridge withdrawals | 6-of-9 | High (100s/day) | Low (<1 min) | Medium |
| Corporate treasury | 5-of-7 | Low (10s/day) | Medium (<10 min) | Low |
| DEX settlement | 3-of-5 | Very high (1000s/day) | Very low (<10 sec) | High |
| Stablecoin mint/burn | 11-of-15 | Medium (100s/day) | Low (<1 min) | High |
| Compliance approval | 3-of-3 | Low (10s/day) | High (<30 min) | Medium |
| DAO treasury | 7-of-12 | Very low (1s/week) | High (hours) | Low |
| Custody withdrawals | Variable | Medium (100s/day) | Medium (<5 min) | Medium |
| Privacy mixing | N-of-N | Medium (10s/round) | Medium (<5 min) | Very high |

---

## Next Steps

- **Understand the protocol**: [How It Works](03-how-it-works.md)
- **Deploy for your use case**: [Deployment Guide](../operators/deployment/01-quickstart-devnet.md)
- **Configure policies**: [Configuration Reference](../operators/configuration/01-configuration-overview.md)

---

**Questions about your specific use case?** File an issue or ask in [Kaspa Discord #igra-support](https://discord.gg/kaspa)
