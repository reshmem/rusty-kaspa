# Build Mode Analysis - Current Behavior

**Date**: 2026-01-07

---

## 🔍 **Current Behavior**

### Default Command (no arguments)

When you run `./run_local_devnet.sh` (which triggers "default" command):

```bash
BUILD_MODE defaults to "clone"  # Line 75
```

### What Gets Built

#### Clone Mode (DEFAULT)
- ✅ **Source Code**: Clones from GitHub
  - `rusty-kaspa`: `https://github.com/reshmem/rusty-kaspa.git` (branch: `devel`)
  - `kaspa-miner`: `https://github.com/IgraLabs/kaspa-miner.git` (branch: `main`)
- ❌ **Config Templates**: From LOCAL repo (where script is located)

#### Local Mode (`--build local`)
- ❌ **Source Code**: From current checkout (`REPO_ROOT`)
- ❌ **Config Templates**: From LOCAL repo (where script is located)

---

## 📂 **Source Locations**

### Script Location Variables (Lines 32-34)
```bash
SCRIPT_DIR = /path/to/rusty-kaspa/wallet/igra/orchestration/devnet/scripts
DEVNET_DIR = /path/to/rusty-kaspa/wallet/igra/orchestration/devnet
REPO_ROOT  = /path/to/rusty-kaspa
```

### Config Template Sources (Lines 171-177)
```bash
ENV_FILE="${DEVNET_DIR}/.env"                             # LOCAL REPO
IGRA_CONFIG_TEMPLATE="${DEVNET_DIR}/igra-devnet.ini"      # LOCAL REPO
HYPERLANE_KEYS_SRC="${DEVNET_DIR}/hyperlane-keys.json"   # LOCAL REPO
KEYSET_JSON_TEMPLATE="${DEVNET_DIR}/devnet-keys.json"    # LOCAL REPO
```

**These are ALWAYS from the local repo where the script is running from.**

### Clone Destinations (Lines 178-180)
```bash
SRC_ROOT="${RUN_ROOT}/sources"                    # /tmp/igra_devnet/sources
RUSTY_SRC="${SRC_ROOT}/rusty-kaspa"               # Cloned GitHub code
MINER_SRC="${SRC_ROOT}/kaspa-miner"               # Cloned GitHub code
```

---

## 🎯 **User Expectation vs Reality**

### User Expectation for "default" Command
> "I expect when I use 'default' it will build from github source, and not from my local repo. It should copy configs and everything from repo we cloned from github."

### Current Reality

| Component | Current Source | User Expects |
|-----------|---------------|--------------|
| **Binary Code** | ✅ GitHub clone | ✅ GitHub clone |
| **Config Templates** | ❌ Local repo | ✅ GitHub clone |

---

## 🤔 **The Issue**

When using clone mode:
1. ✅ Clones `rusty-kaspa` from GitHub to `/tmp/igra_devnet/sources/rusty-kaspa`
2. ✅ Builds binaries from the cloned code
3. ❌ **BUT** uses config templates from local repo:
   - `${DEVNET_DIR}/.env`
   - `${DEVNET_DIR}/igra-devnet.ini`
   - `${DEVNET_DIR}/hyperlane-keys.json`
   - `${DEVNET_DIR}/devnet-keys.json`

4. ❌ **NEVER** uses config templates from the cloned repo:
   - `/tmp/igra_devnet/sources/rusty-kaspa/wallet/igra/orchestration/devnet/.env`
   - `/tmp/igra_devnet/sources/rusty-kaspa/wallet/igra/orchestration/devnet/igra-devnet.ini`
   - etc.

---

## 🔄 **Fallback Mechanism**

There's a fallback from clone → local mode (lines 384-388):

```bash
if [[ -n "${fallback_local}" ]]; then
  BUILD_MODE="local"
  prepare_sources  # Recursively calls with local mode
  return
fi
```

**When does this happen?**
- If GitHub clone fails (network issue, auth issue, etc.)
- Falls back to building from `REPO_ROOT` (your current checkout)

---

## 💡 **Solutions**

### Option 1: Use Cloned Configs (Pure GitHub Build)

Make clone mode use configs from the cloned repo:

```bash
# Around line 171, after determining BUILD_MODE
if [[ "${BUILD_MODE}" == "clone" ]]; then
  # Use configs from cloned repo
  DEVNET_DIR_SOURCE="${RUSTY_SRC}/wallet/igra/orchestration/devnet"
else
  # Use configs from local repo
  DEVNET_DIR_SOURCE="${DEVNET_DIR}"
fi

ENV_FILE="${DEVNET_DIR_SOURCE}/.env"
IGRA_CONFIG_TEMPLATE="${DEVNET_DIR_SOURCE}/igra-devnet.ini"
HYPERLANE_KEYS_SRC="${DEVNET_DIR_SOURCE}/hyperlane-keys.json"
KEYSET_JSON_TEMPLATE="${DEVNET_DIR_SOURCE}/devnet-keys.json"
```

**Problem**: Configs need to be read AFTER cloning, but they're currently set before `ensure_binaries` runs.

**Solution**: Defer config path setup until after cloning:

```bash
# Early in script: Don't set config paths yet
# ...

ensure_binaries() {
  prepare_sources  # This clones or uses local

  # NOW set config paths based on BUILD_MODE
  if [[ "${BUILD_MODE}" == "clone" ]]; then
    CONFIG_SOURCE="${RUSTY_SRC}/wallet/igra/orchestration/devnet"
  else
    CONFIG_SOURCE="${DEVNET_DIR}"
  fi

  ENV_FILE="${CONFIG_SOURCE}/.env"
  IGRA_CONFIG_TEMPLATE="${CONFIG_SOURCE}/igra-devnet.ini"
  # ... etc

  # ... rest of ensure_binaries
}
```

---

### Option 2: Keep Current Behavior (Document It)

**Rationale**:
- Script is part of your repo, so it makes sense to use your repo's configs
- Allows you to customize configs without modifying cloned GitHub repo
- Simpler mental model: "Script uses its own configs"

**Just document clearly**:
```bash
# Note: Config templates always come from the local repo where this script is located,
# even in clone mode. This allows you to customize configs without modifying cloned sources.
```

---

### Option 3: Add a Flag

```bash
--config-source [local|clone]

# Use local configs (default):
./run_local_devnet.sh --build clone --config-source local

# Use cloned configs:
./run_local_devnet.sh --build clone --config-source clone
```

---

## 🎲 **Recommendation**

**Option 1** (Use cloned configs) IF:
- You want a "pure" GitHub experience
- You want to test exactly what's in the GitHub repo
- You don't customize configs locally

**Option 2** (Keep current) IF:
- You customize configs locally
- You want to use the latest code but with your own configs
- Simpler to maintain

**Option 3** (Add flag) IF:
- You want both options available

---

## ❓ **Questions for User**

1. **When you run `default` command, do you want**:
   - [ ] Everything from GitHub (code + configs from cloned repo)
   - [ ] Code from GitHub, but configs from your local repo (current behavior)
   - [ ] Make it configurable with a flag

2. **Do you ever customize the config templates** (`.env`, `igra-devnet.ini`, etc.)?
   - If YES → Keep current behavior (Option 2)
   - If NO → Switch to cloned configs (Option 1)

3. **What's your typical workflow**?
   - Test latest GitHub code with your own settings → Current is good
   - Test exactly what's on GitHub → Need Option 1

---

## 🔧 **Next Steps**

Once you decide, I can implement the solution. The change is straightforward:

**For Option 1** (use cloned configs):
- Move config path setup into `ensure_binaries` after cloning
- Set paths based on `BUILD_MODE`
- Ensure configs exist in cloned repo before using

**For Option 2** (keep current):
- Just document the behavior clearly
- Maybe add a log message explaining where configs come from

**For Option 3** (add flag):
- Add `--config-source` argument parsing
- Set config paths based on flag
- Update usage documentation

Let me know which option you prefer!
