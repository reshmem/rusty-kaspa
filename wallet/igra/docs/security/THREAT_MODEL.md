# Threat Model

## Assets

- Signer private keys and HD mnemonics
- Partial signatures and final transaction data
- Signing event metadata and request IDs

## Trust Boundaries

- JSON-RPC clients are untrusted unless authenticated
- Iroh gossip peers are untrusted until signature-verified
- Kaspa RPC endpoint is trusted for UTXO and submission results

## Threats

- Unauthorized request submission via RPC
- Malicious peer sending forged proposals or finalize messages
- Replay of P2P messages or signing events
- Resource exhaustion through oversized messages or high request rates

## Mitigations

- RPC token authentication and request body size limits
- Signed transport envelopes with replay tracking
- Proposal validation (event hash + PSKT hash + policy enforcement)
- Storage replay checks for events and messages

## Residual Risks

- Coordinator compromise can still attempt invalid requests
- P2P flood still possible without explicit rate limiting per peer
- Operator misconfiguration can weaken security assumptions
