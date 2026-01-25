# PSKT

`service.pskt.redeem_script_hex` defines the multisig redeem script and is the basis for:
- The multisig source address (P2SH/P2SH-like address derived from the redeem script)
- Signature verification order (pubkey order in the script)

## `source_addresses` (Usually Not Needed)

`service.pskt.source_addresses` exists to tell the service which UTXO addresses it may spend from.

In the common case there is **one** multisig source address derived from the redeem script, so:
- Prefer omitting `source_addresses` and letting the service derive it, or
- Set it to a single-element list containing the derived address.

