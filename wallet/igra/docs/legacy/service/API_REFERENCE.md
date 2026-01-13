# API Reference

## HTTP Endpoints

### `POST /rpc`
JSON-RPC 2.0 endpoint.

### `GET /health`
Returns basic liveness.

```json
{ "status": "healthy" }
```

### `GET /ready`
Returns readiness based on storage + node RPC connectivity.

```json
{
  "status": "ready",
  "storage_ok": true,
  "node_connected": true
}
```

### `GET /metrics`
Returns Prometheus-formatted metrics.

## JSON-RPC Methods

### `signing_event.submit`

Params:

```json
{
  "session_id_hex": "<32-byte-hex>",
  "request_id": "req-001",
  "coordinator_peer_id": "coordinator-1",
  "expires_at_nanos": 1710000000000000000,
  "signing_event": {
    "event_id": "event-001",
    "event_source": { "api": { "issuer": "bridge-service" } },
    "derivation_path": "m/45'/111111'/0'/0/0",
    "derivation_index": 0,
    "destination_address": "kaspatest:...",
    "amount_sompi": 123456,
    "metadata": { "reason": "payout" },
    "timestamp_nanos": 1710000000000000000,
    "signature_hex": null
  }
}
```

Result:

```json
{
  "session_id_hex": "<32-byte-hex>",
  "event_hash_hex": "<32-byte-hex>",
  "validation_hash_hex": "<32-byte-hex>"
}
```

Errors:

- `-32602`: invalid params
- `-32000`: processing failed
- `-32001`: unauthorized

## Storage Schema (RocksDB)

- `evt:` SigningEvent indexed by `event_hash`
- `req:` SigningRequest indexed by `request_id`
- `proposal:` StoredProposal indexed by `request_id`
- `req_input:` RequestInput entries
- `req_ack:` SignerAckRecord entries
- `req_sig:` PartialSigRecord entries
- `seen:` transport replay markers
