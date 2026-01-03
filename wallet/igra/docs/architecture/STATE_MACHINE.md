# Signing Request State Machine

## States

- Pending: Request received, waiting for validation and coordination
- Approved: Request validated by signers, collecting signatures
- Finalized: Threshold met and transaction finalized
- Rejected: Policy violation or validation failure
- Expired: Session timeout reached without threshold
- Aborted: Coordinator failure or manual abort

## Transitions

```
       +---------+
       | Pending |
       +----+----+
            |
    +-------+-------+
    |       |       |
    v       v       v
+--------+ +--------+ +---------+
|Rejected| |Approved| |Expired  |
+--------+ +----+---+ +---------+
               |
       +-------+-------+
       |       |       |
       v       v       v
+---------+ +--------+ +---------+
|Finalized| |Aborted | |Expired  |
+---------+ +--------+ +---------+
```

Note: Pending may transition directly to Finalized when threshold signatures are reached without an intermediate Approved state.

## Invariants

1. Terminal states (Finalized, Rejected, Expired, Aborted) never transition to another state
2. Finalized requires threshold signatures collected
3. Rejected requires policy violation or validation failure
4. Expired requires session_timeout elapsed without threshold
