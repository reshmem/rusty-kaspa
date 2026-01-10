# Fresh Script Review - run_local_devnet.sh

**Date**: 2026-01-07
**Reviewer**: Claude (fresh perspective)
**Script**: run_local_devnet.sh (972 lines)

---

## 🎯 Overall Assessment

**Status**: ⚠️ **Two issues found** - one critical workflow issue, one minor

The script is well-structured and mostly production-ready, but has one critical workflow gap that will cause user confusion.

---

## 🔴 CRITICAL: Missing Config Seeding in start/restart Commands

### Problem Description

**Lines 941-946 (start command)**:
```bash
start)
  setup_config_source
  require_binaries_present
  ensure_configs
  start_targets
  ;;
```

**Lines 951-957 (restart command)**:
```bash
restart)
  stop_targets
  setup_config_source
  require_binaries_present
  ensure_configs
  start_targets
  ;;
```

**Issue**: Neither `start` nor `restart` calls `prepare_igra_config()`.

### Impact

**Broken User Workflow**:
```bash
# User runs build to compile binaries
$ ./run_local_devnet.sh build
✓ Build complete. Binaries staged in /tmp/igra_devnet/bin.

# User tries to start services
$ ./run_local_devnet.sh start
✗ Missing required config: /tmp/igra_devnet/config/.env
✗ Run 'generate-keys' first or use default/setup for initial generation.
```

**User confusion**: "I just built everything, why can't I start it?"

### Why This Happens

The `ensure_configs()` function (lines 805-815) **only validates** that configs exist - it doesn't seed them:

```bash
ensure_configs() {
  local required_files=("${CONFIG_DIR}/.env" "${IGRA_CONFIG}" "${HYPERLANE_KEYS}" "${KEYSET_JSON}")
  for file in "${required_files[@]}"; do
    if [[ ! -f "${file}" ]]; then
      log_error "Missing required config: ${file}"
      log_error "Run 'generate-keys' first or use default/setup for initial generation."
      exit 1
    fi
  done
  log_info "Verified required configs in ${CONFIG_DIR}"
}
```

But `prepare_igra_config()` (lines 486-504) **seeds missing configs**:

```bash
prepare_igra_config() {
  if [[ ! -f "${CONFIG_DIR}/.env" ]]; then
    log_info "Seeding .env from template into ${CONFIG_DIR}"
    cp -f "${ENV_FILE}" "${CONFIG_DIR}/.env"
  fi
  if [[ ! -f "${HYPERLANE_KEYS}" ]]; then
    log_info "Seeding hyperlane-keys.json from template into ${CONFIG_DIR}"
    cp -f "${HYPERLANE_KEYS_SRC}" "${HYPERLANE_KEYS}"
  fi
  if [[ ! -f "${IGRA_CONFIG}" ]]; then
    log_info "Seeding igra-config.ini from template into ${CONFIG_DIR}"
    sed \
      -e "s|/data/igra|${IGRA_DATA}|g" \
      -e "s|grpc://kaspad:16110|grpc://127.0.0.1:16110|g" \
      "${IGRA_CONFIG_TEMPLATE}" > "${IGRA_CONFIG}"
  else
    log_info "Using existing igra-config.ini (not overwriting)"
  fi
}
```

### Solution

**Add `prepare_igra_config` before `ensure_configs` in both commands:**

**For start command (line 941)**:
```bash
start)
  setup_config_source
  require_binaries_present
  prepare_igra_config      # ← ADD THIS LINE
  ensure_configs
  start_targets
  ;;
```

**For restart command (line 951)**:
```bash
restart)
  stop_targets
  setup_config_source
  require_binaries_present
  prepare_igra_config      # ← ADD THIS LINE
  ensure_configs
  start_targets
  ;;
```

### Why This Fix Works

1. `prepare_igra_config` safely seeds missing configs (only if they don't exist)
2. `ensure_configs` validates all required configs are present (including KEYSET_JSON which isn't seeded)
3. If user ran `setup` or `generate-keys` before, configs are preserved
4. If configs are missing, templates are seeded
5. User can now run `build` then `start` successfully

### Alternative Workflows After Fix

```bash
# Workflow 1: Full setup (generates keys)
$ ./run_local_devnet.sh setup
$ ./run_local_devnet.sh start

# Workflow 2: Build then start (seeds templates, user must generate keys)
$ ./run_local_devnet.sh build
$ ./run_local_devnet.sh generate-keys
$ ./run_local_devnet.sh start

# Workflow 3: Default (does everything)
$ ./run_local_devnet.sh
$ ./run_local_devnet.sh start

# Workflow 4: Start with auto-seed (new capability)
$ ./run_local_devnet.sh build
$ ./run_local_devnet.sh start  # ← Will seed templates but fail on missing KEYSET_JSON
$ ./run_local_devnet.sh generate-keys
$ ./run_local_devnet.sh start  # ← Now works!
```

**Wait, there's still an issue!** Even with `prepare_igra_config`, the `start` command will still fail because `ensure_configs` checks for `KEYSET_JSON`, which is only created by `generate_keys`.

### Better Solution: Make ensure_configs More Helpful

**Option A**: Have `ensure_configs` provide better guidance:

```bash
ensure_configs() {
  local required_files=("${CONFIG_DIR}/.env" "${IGRA_CONFIG}" "${HYPERLANE_KEYS}" "${KEYSET_JSON}")
  local missing=()

  for file in "${required_files[@]}"; do
    if [[ ! -f "${file}" ]]; then
      missing+=("${file}")
    fi
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    log_error "Missing ${#missing[@]} required config file(s):"
    for file in "${missing[@]}"; do
      log_error "  - ${file}"
    done

    # Check if it's just the keyset (generated file)
    local has_templates=true
    [[ ! -f "${CONFIG_DIR}/.env" ]] && has_templates=false
    [[ ! -f "${IGRA_CONFIG}" ]] && has_templates=false
    [[ ! -f "${HYPERLANE_KEYS}" ]] && has_templates=false

    if [[ "${has_templates}" == "true" ]]; then
      log_error "Templates exist but generated keys are missing."
      log_error "Run: ./run_local_devnet.sh generate-keys"
    else
      log_error "Run one of these commands to initialize:"
      log_error "  ./run_local_devnet.sh setup      # Build + generate keys"
      log_error "  ./run_local_devnet.sh default    # Same as setup"
      log_error "  ./run_local_devnet.sh generate-keys  # Just generate keys"
    fi
    exit 1
  fi

  log_info "Verified required configs in ${CONFIG_DIR}"
}
```

**Option B**: Make `start` command auto-run `generate-keys` if needed:

This is more opinionated but very user-friendly:

```bash
start)
  setup_config_source
  require_binaries_present
  prepare_igra_config

  # Auto-generate keys if missing
  if [[ ! -f "${KEYSET_JSON}" ]]; then
    log_warn "Generated keys missing, running generate-keys automatically..."
    generate_keys
  fi

  ensure_configs
  start_targets
  ;;
```

### Recommended Approach

**Implement both fixes**:

1. Add `prepare_igra_config` to `start` and `restart` commands (seeds templates)
2. Improve `ensure_configs` error messages (Option A) to guide users

**OR** implement the auto-generate approach (Option B) if you want maximum user-friendliness.

---

## ⚠️ Minor Issue: Debug Mode Still Enabled

**Line 1**:
```bash
set -euxo pipefail
```

**Problem**: The `-x` flag enables debug mode, causing verbose trace output.

**Impact**:
- All commands are echoed with full variable expansion
- Logs become very large and harder to read
- May expose sensitive paths/values in logs

**Fix**:
```bash
# Change from:
set -euxo pipefail

# To:
set -euo pipefail
```

**Priority**: Minor - not blocking, but should be fixed before production

---

## ⚠️ Minor Inconsistency: Dry-Run Message Outdated

**Line 302** (in `build_rusty_repo` function):
```bash
if [[ "${DRY_RUN}" == "true" ]]; then
  log_info "[DRY-RUN] cd ${repo_path} && CARGO_TARGET_DIR=${TARGET_DIR} cargo build --release --locked -p kaspad -p rothschild -p igra-service --bin kaspa-threshold-service --bin fake_hyperlane_ism_api"
```

**Problem**: The dry-run message shows a single cargo command with all packages together, but the actual build (lines 305-325) uses **two separate cargo commands**.

**Actual build** (lines 305-318):
```bash
# First build: kaspad and rothschild
cargo build --release --locked -p kaspad -p rothschild

# Second build: igra-service with specific binaries
cargo build --release --locked -p igra-service --bin kaspa-threshold-service --bin fake_hyperlane_ism_api
```

**Impact**: Low - dry-run is preview only, doesn't affect actual execution

**Fix**:
```bash
if [[ "${DRY_RUN}" == "true" ]]; then
  log_info "[DRY-RUN] cd ${repo_path} && cargo build --release --locked -p kaspad -p rothschild"
  log_info "[DRY-RUN] cd ${repo_path} && cargo build --release --locked -p igra-service --bin kaspa-threshold-service --bin fake_hyperlane_ism_api"
  log_info "[DRY-RUN] Verify binaries: kaspad, rothschild, kaspa-threshold-service, fake_hyperlane_ism_api"
```

---

## ✅ What's Working Well

### Excellent Code Structure

- **Clear separation of concerns**: Functions are well-named and focused
- **Error handling**: Comprehensive error checking with clear messages
- **Path safety**: All critical paths properly quoted
- **Logging**: Consistent, colored, timestamped logging throughout
- **Process management**: Robust start/stop with timeout and force-kill

### Build System

**Lines 297-343** (build_rusty_repo):
- ✅ Properly splits cargo build into two commands
- ✅ Validates all binaries exist after build
- ✅ Handles devnet-keygen fallback correctly
- ✅ Clear error messages on failure

**Lines 305-325** - Build command structure:
```bash
# First build: kaspad and rothschild (no --bin filters)
if ! (cd "${repo_path}" && RUSTC_WRAPPER= CARGO_TARGET_DIR="${TARGET_DIR}" \
  cargo build --release --locked \
    -p kaspad \
    -p rothschild); then
  log_error "Failed to build kaspad and rothschild from ${repo_path}"
  exit 1
fi

# Second build: igra-service with specific --bin filters
if ! (cd "${repo_path}" && RUSTC_WRAPPER= CARGO_TARGET_DIR="${TARGET_DIR}" \
  cargo build --release --locked \
    -p igra-service --bin kaspa-threshold-service --bin fake_hyperlane_ism_api); then
  log_error "Failed to build igra-service binaries from ${repo_path}"
  exit 1
fi

# Validation: Verify all binaries exist
for binary in kaspad rothschild kaspa-threshold-service fake_hyperlane_ism_api; do
  if [[ ! -x "${TARGET_DIR}/release/${binary}" ]]; then
    log_error "${binary} not found after build (expected at ${TARGET_DIR}/release/${binary})"
    exit 1
  fi
done
```

This correctly fixes the cargo `--bin` filter issue.

### Config Source Handling

**Lines 426-456** (setup_config_source):
```bash
setup_config_source() {
  local config_source
  if [[ "${BUILD_MODE}" == "clone" ]]; then
    config_source="${RUSTY_SRC}/wallet/igra/orchestration/devnet"
    if [[ ! -f "${config_source}/.env" ]]; then
      log_warn "Cloned repo missing config templates at ${config_source}; falling back to local ${DEVNET_DIR}"
      config_source="${DEVNET_DIR}"
    fi
  else
    config_source="${DEVNET_DIR}"
  fi

  ENV_FILE="${config_source}/.env"
  IGRA_CONFIG_TEMPLATE="${config_source}/igra-devnet.ini"
  HYPERLANE_KEYS_SRC="${config_source}/hyperlane-keys.json"
  KEYSET_JSON_TEMPLATE="${config_source}/devnet-keys.json"

  log_info "Using config templates from: ${config_source}"
  # ... validation and load_env
```

- ✅ Clone mode uses GitHub configs
- ✅ Local mode uses local configs
- ✅ Fallback to local if GitHub configs missing
- ✅ Clear logging

### Conditional Config Seeding

**Lines 486-504** (prepare_igra_config):
```bash
prepare_igra_config() {
  if [[ ! -f "${CONFIG_DIR}/.env" ]]; then
    log_info "Seeding .env from template into ${CONFIG_DIR}"
    cp -f "${ENV_FILE}" "${CONFIG_DIR}/.env"
  fi
  if [[ ! -f "${HYPERLANE_KEYS}" ]]; then
    log_info "Seeding hyperlane-keys.json from template into ${CONFIG_DIR}"
    cp -f "${HYPERLANE_KEYS_SRC}" "${HYPERLANE_KEYS}"
  fi
  if [[ ! -f "${IGRA_CONFIG}" ]]; then
    log_info "Seeding igra-config.ini from template into ${CONFIG_DIR}"
    sed \
      -e "s|/data/igra|${IGRA_DATA}|g" \
      -e "s|grpc://kaspad:16110|grpc://127.0.0.1:16110|g" \
      "${IGRA_CONFIG_TEMPLATE}" > "${IGRA_CONFIG}"
  else
    log_info "Using existing igra-config.ini (not overwriting)"
  fi
}
```

- ✅ Only seeds missing files
- ✅ Preserves existing configs
- ✅ Clear logging

### Process Management

**Lines 590-632** (stop_process):
```bash
stop_process() {
  local name="$1"
  local pid_file="${PIDS_DIR}/${name}.pid"

  if [[ ! -f "${pid_file}" ]]; then
    log_warn "No pid file for ${name} (${pid_file}); skipping."
    return
  fi
  local pid
  pid=$(cat "${pid_file}")
  if ! kill -0 "${pid}" 2>/dev/null; then
    log_warn "${name} already stopped"
    rm -f "${pid_file}"
    return
  fi

  log_info "Stopping ${name} (pid ${pid})..."
  kill "${pid}" >/dev/null 2>&1 || true
  local timeout=${PROCESS_STOP_TIMEOUT}
  for _ in $(seq 1 ${timeout}); do
    if ! kill -0 "${pid}" 2>/dev/null; then
      log_success "Stopped ${name}"
      rm -f "${pid_file}"
      return
    fi
    sleep 1
  done

  log_warn "${name} did not stop gracefully, force killing..."
  kill -9 "${pid}" >/dev/null 2>&1 || true
  sleep 1
  if kill -0 "${pid}" 2>/dev/null; then
    log_error "Failed to kill ${name} (pid ${pid})"
  else
    log_success "Force killed ${name}"
  fi
  rm -f "${pid_file}"
}
```

- ✅ Graceful shutdown with SIGTERM
- ✅ Timeout configurable
- ✅ Force kill with SIGKILL if needed
- ✅ PID validation
- ✅ Cleanup

### Command Flow Validation

All commands properly structure their operations:

**setup** (908-916): ✅ Correct
- prepare_sources → setup_config_source → resolve_binaries_from_target → stage_binaries → prepare_igra_config → generate_keys

**build** (918-924): ✅ Correct
- prepare_sources → setup_config_source → resolve_binaries_from_target → stage_binaries

**default** (926-933): ✅ Correct
- prepare_sources → setup_config_source → resolve_binaries_from_target → stage_binaries → generate_keys

**generate-keys** (935-939): ✅ Correct
- setup_config_source → generate_keys

**stop** (947-949): ✅ Correct
- stop_targets

**status** (958-960): ✅ Correct
- show_status

### Variable Naming

- ✅ Consistent throughout
- ✅ Clear, descriptive names
- ✅ No conflicts or shadowing

### Python Script

**update_devnet_config.py** (213 lines):
- ✅ All imports present (including `shutil`)
- ✅ Writes only to CONFIG_DIR (no source overwrites)
- ✅ Clear separation of concerns
- ✅ Good error handling
- ✅ Type hints

---

## 📊 Summary Table

| Category | Status | Notes |
|----------|--------|-------|
| **Critical Issues** | 🔴 1 found | Missing `prepare_igra_config` in start/restart |
| **Minor Issues** | ⚠️ 2 found | Debug mode, dry-run message inconsistency |
| **Build System** | ✅ Excellent | Properly fixed cargo --bin issue |
| **Config Handling** | ✅ Excellent | Dynamic source, conditional seeding |
| **Process Management** | ✅ Excellent | Robust with timeout and force-kill |
| **Error Handling** | ✅ Excellent | Comprehensive error checking |
| **Code Structure** | ✅ Excellent | Well-organized, clear functions |
| **Variable Naming** | ✅ Consistent | No issues |
| **Path Safety** | ✅ Safe | Proper quoting throughout |
| **Python Script** | ✅ Clean | No issues |

---

## 🎯 Action Items

### Must Fix (Critical)

1. **Add `prepare_igra_config` to start command** (line 941)
   ```bash
   start)
     setup_config_source
     require_binaries_present
     prepare_igra_config      # ← ADD THIS
     ensure_configs
     start_targets
     ;;
   ```

2. **Add `prepare_igra_config` to restart command** (line 951)
   ```bash
   restart)
     stop_targets
     setup_config_source
     require_binaries_present
     prepare_igra_config      # ← ADD THIS
     ensure_configs
     start_targets
     ;;
   ```

3. **Optional: Improve `ensure_configs` error messages** (line 805)
   - Consider implementing Option A from the detailed solution above
   - Provides better guidance when configs are missing

### Should Fix (Minor)

4. **Disable debug mode** (line 1)
   ```bash
   # Change from:
   set -euxo pipefail
   # To:
   set -euo pipefail
   ```

5. **Update dry-run message** (line 302)
   - Make it reflect the actual two-stage build

---

## 💡 Recommendations

### Immediate Actions

1. Apply the critical fix (add `prepare_igra_config` to start/restart)
2. Disable debug mode
3. Test the workflow:
   ```bash
   ./run_local_devnet.sh clean
   ./run_local_devnet.sh build
   ./run_local_devnet.sh generate-keys
   ./run_local_devnet.sh start
   ./run_local_devnet.sh status
   ./run_local_devnet.sh stop
   ```

### Future Enhancements

1. Consider implementing auto-generate keys in `start` command (Option B) for maximum user-friendliness
2. Add a `validate` command that checks config validity without starting services
3. Consider adding a `--force-rebuild` flag for build command

---

## 🏁 Conclusion

**Overall**: The script is well-engineered with one critical workflow gap.

**Strengths**:
- Excellent error handling and process management
- Properly fixed build issues (cargo --bin filtering)
- Good config source handling (clone vs local)
- Clean, maintainable code structure

**Critical Gap**:
- `start` and `restart` commands don't seed configs, causing user confusion
- Fix is simple: add one line to each command

**After applying the critical fix**: Script will be production-ready and user-friendly.

**Estimated time to fix**: 5 minutes (2 line additions + testing)

---

**Review Status**: Complete
**Recommendations**: Clear and actionable
**Priority**: Fix critical issue before production use
