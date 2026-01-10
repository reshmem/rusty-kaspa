# Igra Docker (Devnet)

This builds the Igra service from the forked repo `reshmem/rusty-kaspa` on the `devel` branch and runs the `kaspa-threshold-service` binary.

## Build

This Dockerfile clones the repo over SSH. Use SSH forwarding when building:

```bash
docker build --ssh default -t igra-service \
  --build-arg IGRA_REPO=git@github.com:reshmem/rusty-kaspa.git \
  --build-arg IGRA_REF=devel \
  -f orchestration/devnet/igra/Dockerfile .
```

## Run

Mount a config file and data directory:

```bash
docker run --rm -p 8088:8088 \
  -v $(pwd)/orchestration/devnet/igra-devnet.toml:/data/igra/igra-config.toml \
  -v $(pwd)/.igra:/data/igra \
  igra-service
```

Notes:
- The service uses `KASPA_DATA_DIR=/data/igra` by default.
- Config is loaded from `/data/igra/igra-config.toml` unless `KASPA_CONFIG_PATH` is set.
