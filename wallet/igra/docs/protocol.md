# Protocol Overview

Igra processes external “signing events” and reaches multi-signer agreement using:
- CRDT gossip (state dissemination)
- A two-phase coordination loop (proposal → commit)
- PSKT construction + per-signer partial signing

Code is the source of truth; use these entry points:
- Event processing: `igra-core/src/application/event_processor.rs`
- Signing: `igra-core/src/application/pskt_signing.rs`
- Service wiring: `igra-service/src/bin/kaspa-threshold-service.rs`

