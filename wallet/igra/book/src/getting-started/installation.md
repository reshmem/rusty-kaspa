# Installation

## Prerequisites

- Rust 1.75+ (`rustc --version`)
- A Kaspa node (local `kaspad`) for RPC
- Linux (recommended), macOS, or Windows

## Build from Source

```bash
git clone https://github.com/kaspanet/rusty-kaspa.git
cd rusty-kaspa/wallet/igra

cargo build --release --bin kaspa-threshold-service
./target/release/kaspa-threshold-service --help
```

## Next Steps

- [Quick Start](quickstart.md)
- [Network Modes](../configuration/network-modes.md)

