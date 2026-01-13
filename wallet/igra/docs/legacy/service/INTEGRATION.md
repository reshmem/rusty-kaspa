# Integration Guide (Bridge Operators)

This guide shows how to submit signing events and handle responses.

## JSON-RPC Endpoint

- URL: `http://<host>:<port>/rpc`
- Method: `signing_event.submit`
- Optional auth: `Authorization: Bearer <token>` or `x-api-key: <token>`

## Request Example

```bash
curl -s http://127.0.0.1:8088/rpc \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "signing_event.submit",
    "params": {
      "session_id_hex": "0101010101010101010101010101010101010101010101010101010101010101",
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
  }'
```

## Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "session_id_hex": "<32-byte-hex>",
    "event_hash_hex": "<32-byte-hex>",
    "validation_hash_hex": "<32-byte-hex>"
  }
}
```

## Error Handling

- `-32602`: invalid params / schema mismatch.
- `-32000`: processing failure (policy rejection, invalid signature, or replay).
- `-32001`: auth failure.

## Retry Policy

- Retry transient failures (connection issues).
- Do not retry on `event_hash` replay errors; create a new event id instead.

