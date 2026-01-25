# Refactoring `devel` git history (plan + execution notes)

## What I understand you’re asking for

You’re on the `devel` branch and you want a written proposal for how to refactor its git history before sharing/merging it. Concretely:

- Suggest a practical workflow for rewriting history (interactive rebase / squash / split where needed).
- Replace the current “WIP/checkpoint” commit subjects with informative **one-line** subjects.
- Prefer conventional-commit style prefixes like `feat:`, `fix:`, `refactor:`, `docs:`, `chore:`, etc.
- Provide **one suggested subject per commit**, extracted from the original `master..devel` history (now kept as `devel-backup`).

## Status

- `devel` was squashed locally into 14 logical commits (no push done).
- The pre-squash history is preserved at `devel-backup`.

## Safety notes (history rewriting)

- Rewriting `devel` changes commit hashes; anyone with the old history must rebase/reset.
- Always start by creating a backup pointer:
  - `git branch devel-backup`
- When pushing rewritten history, prefer:
  - `git push --force-with-lease origin devel`

## Recommended workflow

1. Find the base of `devel` (where it diverged from `master`):
   - `BASE=$(git merge-base devel master)`
2. Start an interactive rebase from that base:
   - `git rebase -i "$BASE"`
3. In the rebase todo:
   - Use `reword` to apply the proposed subjects below.
   - Optionally replace “micro-WIP” commits with `fixup` under the nearest logical commit.
   - If a commit mixes docs + code and you want clean separation, mark it `edit` and split it (`git reset HEAD^`, then `git add -p` + multiple `git commit`).

## Proposed one-line subjects per commit (`master..devel`, oldest → newest)

Note: These hashes refer to the pre-squash history (see `devel-backup`). After rewriting history, hashes will change.

If any line feels “too generic”, use `git show <hash>` and tighten the wording.

9994ec81 feat(igra): bootstrap threshold-signing workspace (core, service, orchestration, docs)
36f7b22e chore(devnet): wire docker-compose env and fake hyperlane ISM binary
8ad96f97 chore(devnet): update kaspaminer Dockerfile
31fe5804 chore(devnet): adjust devnet docker-compose and igra image
59262185 chore(devnet): align docker-compose with kaspa miner image
3ae6679f docs(devnet): update devnet README and docker-compose wiring
1931d058 chore(devnet): tweak kaspaminer image build
25849905 chore(devnet): align docker-compose with kaspaminer changes
cacacbcf chore(devnet): add Makefile targets and tune docker-compose
68a3dc84 chore(devnet): add env defaults and update kaspad/igra images
4ac991f4 chore(devnet): sync core config loader with devnet templates and scripts
f3e9fb27 chore(devnet): tweak `run_local_devnet.sh`
295162ef chore(devnet): update devnet ini and local run script
0dbc27c3 refactor(config): adjust config loader behavior
2c0db454 chore(devnet): update devnet config generation script
56978a21 refactor(igra-service): improve service setup for local devnet runs
eeda7ebc feat(devnet): extend keygen and fake hyperlane binaries
72844dc0 chore(devnet): update keygen defaults and devnet ini
7aa26511 chore(devnet): refine local devnet scripts
3e9f5ee6 chore(devnet): keep keygen/fake-hyperlane in sync with devnet scripts
d70b1eff chore(devnet): align keygen integration in devnet scripts
c18a1219 refactor(config): align core/service config types and devnet scripts
fce66966 refactor(igra-service): refactor service binary setup flow
af30cccc chore(devnet): align service setup with local devnet script
595694bb refactor(pskt): update builder/keygen integration for devnet flows
d78183f4 chore(devnet): sync keygen with devnet scripts
be1c02bb feat(config): add config encryption, persistence, and validation plumbing
3c86b807 feat(rothschild): add `--amount` flag (sompi)
815d01e0 feat(rothschild): add `--network` flag
48db18e6 chore(devnet): add `run_rothschild.sh` helper script
a7b2eb94 feat(devnet): add balance-check tooling (binary + scripts)
c98dffb7 chore(devnet): refine balance-check script and local run flow
cbef1b91 refactor(config): introduce unified config loader and update devnet tools
0f30d817 docs(architecture): add domain/infrastructure and testing deep dives
fd6a1899 docs(dev-proc): add bug tracking and refactoring process notes
cd43131b chore: clippy fixes and minor core refactors
03cd9f51 refactor(igra-core): refactor coordinator/event pipeline structure
3c799809 chore(config): add TOML artifacts and move/refile documentation
3c4b4a50 feat(igra-service): introduce dedicated CLI module for service binary
69f548ee refactor(api): align signing-event handlers with setup and devnet Dockerfile
2ba79824 refactor(igra-core): simplify signer and request state machine plumbing
a38aa8de feat(api): add health/rpc endpoints and hyperlane watcher plumbing
2a495eb3 chore(hyperlane): align handlers with fake ISM binary and devnet scripts
7ad4afac refactor(validation): tighten domain event validation
aaab7da7 fix(hyperlane): adjust hyperlane validation between core and service
3d53f7d6 refactor(hyperlane): factor hyperlane validation types
6f450bce refactor(igra-core): reshape coordinator/event processor before CRDT switch
eab6909f refactor(logging): introduce structured logging constants module
037b9ff1 chore(hyperlane): update fake ISM API binary behavior
889dcd7a chore(logging): sync logging module dependencies
9203dd5a chore(logging): tweak logging configuration defaults
617a8651 refactor(logging): adjust logging constants
e022b663 refactor(logging): reorganize logging module structure
1ec64c7e refactor(storage): update rocks engine; align hyperlane handler logging
d13793b8 refactor(pskt): adjust PSKT builder integration with coordinator
f15dfc04 docs(logging): capture logger integration notes and follow-ups
55569fdf refactor(crdt): introduce CRDT event-state model and coordinator
8ba785ce refactor(storage): align storage traits and config types for CRDT
4bb0ae57 feat(flow): integrate CRDT coordination with signing flow and tests
b30c1559 refactor(iroh): update iroh client and PSKT multisig wiring
c558c152 refactor(storage): harden CRDT storage and iroh message encoding
d1327f4f chore(devnet): update keygen and config validation for devnet
e33ce8e3 chore(devnet): align PSKT builder and devnet scripts with fake hyperlane
6c1415b4 refactor(igra-service): refine CRDT coordination handler
db2dede3 refactor(flow): tweak PSKT builder integration in coordination flow
dc002eac feat(rpc): support end-to-end devnet 2-of-3 flow
809bb596 refactor(model): simplify domain model and add normalization layer
95a69463 refactor(igra-core): tighten event processing and foundation utilities
9c412e72 docs: move legacy documentation under `docs/legacy/`
704df6bb docs(security): add SOC2 notes and legacy cleanup docs
ea769bac refactor(igra-core): refine CRDT data types and monitoring paths
387d7aaa docs(protocol): add CRDT gossip fixes, two-phase review notes, and TODOs
144ad9cf docs(protocol): add two-phase protocol notes and hyperlane integration doc
bbc07ca8 feat(protocol): implement two-phase coordination flow
a5971e14 feat(storage): add phase storage for two-phase coordination
84e383bf fix(igra-service): resolve CRDT ↔ two-phase handler integration issues
9e2fefed fix(flow): align PSKT params with two-phase flow and kaspa integration
2296ed99 refactor(storage): finalize phase storage and error handling
44d3193a refactor(protocol): refine proposer selection and service handler wiring
9e57d51b test(storage): add integration coverage for phase storage
959f536d refactor(iroh): improve iroh client behavior
52614bdf refactor(api): reorganize events/rpc handlers
8f70469b refactor(igra-core): tighten validation, normalization, and policy enforcement
4d34795e feat(coordination): add unfinalized reporter; update two-phase algo notes
f4166005 feat(hyperlane): add devnet endpoints, fake relayer, and storage support
11c95272 docs(ops): add observability/how-to notes; refine coordination flow
cf520400 feat(metrics): add stats for submitted events vs txs sent
068bf334 refactor(hex): centralize hex encoding helpers; add audit and refactor notes
af131b01 feat(keys): add secret-store backends and `secrets-admin` tooling
bed9440e refactor(igra): modularize CRDT coordination; expand docs and config guides
83c7b3e1 fix(config): align config loader rules with mainnet templates and docs
567e7c36 refactor(config): harden startup/secret rules and refresh config templates/docs

## Current squashed `devel` history (14 commits)

Run `git log --reverse --oneline master..devel` to see the current hashes. The expected subjects are:

- feat(igra): bootstrap threshold-signing workspace
- chore(devnet): add docker-based devnet and scripts
- feat(config): add config wiring and hardening (encryption/validation)
- feat(devnet): add rothschild CLI flags and unify config loader
- docs(dev-proc): add architecture/testing and refactoring notes
- refactor(core): refactor coordinator and add config artifacts
- refactor(igra-service): improve CLI/API plumbing, validation, and logging
- refactor(crdt): introduce CRDT coordinator/storage and enable e2e devnet flow
- refactor(model): simplify domain model and consolidate mid-stream docs/checkpoints
- feat(protocol): implement two-phase coordination and harden service integration
- feat(hyperlane): add devnet endpoints and fake relayer tooling
- feat(metrics): add stats for submitted events vs txs sent
- feat(security): centralize hex encoding and add secret-store tooling
- docs(config): add mdBook + mainnet config guides; modularize coordination

## Squash plan (≈14 commits, no reordering)

This is an alternative plan that reduces the 92 `master..devel` commits into **14 logical commits** by keeping an “anchor” commit (the first in each contiguous group) and marking the rest as `fixup`.

Design goals:

- No commit reordering (minimizes conflict risk).
- Clean, reviewable commit subjects.
- Group by major themes: devnet/orchestration, config system, docs, pre-CRDT refactors, CRDT, model, protocol, hyperlane, metrics, security/key-management, docs+book.

### Resulting commits (what the final history looks like)

1. `feat(igra): bootstrap threshold-signing workspace`
   - Keep: `9994ec81`
2. `chore(devnet): add docker-based devnet and scripts`
   - Keep: `36f7b22e`
   - Fixup: `8ad96f97`, `31fe5804`, `59262185`, `3ae6679f`, `1931d058`, `25849905`, `cacacbcf`, `68a3dc84`, `4ac991f4`, `f3e9fb27`, `295162ef`, `0dbc27c3`, `2c0db454`, `56978a21`, `eeda7ebc`, `72844dc0`, `7aa26511`, `3e9f5ee6`, `d70b1eff`
3. `feat(config): add config wiring and hardening (encryption/validation)`
   - Keep: `c18a1219`
   - Fixup: `fce66966`, `af30cccc`, `595694bb`, `d78183f4`, `be1c02bb`
4. `feat(devnet): add rothschild CLI flags and unify config loader`
   - Keep: `3c86b807`
   - Fixup: `815d01e0`, `48db18e6`, `a7b2eb94`, `c98dffb7`, `cbef1b91`
5. `docs(dev-proc): add architecture/testing and refactoring notes`
   - Keep: `0f30d817`
   - Fixup: `fd6a1899`
6. `refactor(core): refactor coordinator and add config artifacts`
   - Keep: `cd43131b`
   - Fixup: `03cd9f51`, `3c799809`
7. `refactor(igra-service): improve CLI/API plumbing, validation, and logging`
   - Keep: `3c4b4a50`
   - Fixup: `69f548ee`, `2ba79824`, `a38aa8de`, `2a495eb3`, `7ad4afac`, `aaab7da7`, `3d53f7d6`, `6f450bce`, `eab6909f`, `037b9ff1`, `889dcd7a`, `9203dd5a`, `617a8651`, `e022b663`, `1ec64c7e`, `d13793b8`, `f15dfc04`
8. `refactor(crdt): introduce CRDT coordinator/storage and enable e2e devnet flow`
   - Keep: `55569fdf`
   - Fixup: `8ba785ce`, `4bb0ae57`, `b30c1559`, `c558c152`, `d1327f4f`, `e33ce8e3`, `6c1415b4`, `db2dede3`, `dc002eac`
9. `refactor(model): simplify domain model and consolidate mid-stream docs/checkpoints`
   - Keep: `809bb596`
   - Fixup: `95a69463`, `9c412e72`, `704df6bb`, `ea769bac`, `387d7aaa`, `144ad9cf`
10. `feat(protocol): implement two-phase coordination and harden service integration`
   - Keep: `bbc07ca8`
   - Fixup: `a5971e14`, `84e383bf`, `9e2fefed`, `2296ed99`, `44d3193a`, `9e57d51b`, `959f536d`, `52614bdf`, `8f70469b`, `4d34795e`
11. `feat(hyperlane): add devnet endpoints and fake relayer tooling`
   - Keep: `f4166005`
   - Fixup: `11c95272`
12. `feat(metrics): add stats for submitted events vs txs sent`
   - Keep: `cf520400`
13. `feat(security): centralize hex encoding and add secret-store tooling`
   - Keep: `068bf334`
   - Fixup: `af131b01`
14. `docs(config): add mdBook + mainnet config guides; modularize coordination`
   - Keep: `bed9440e`
   - Fixup: `83c7b3e1`, `567e7c36`

### Interactive rebase todo (copy/paste guide)

Run:

- `BASE=$(git merge-base devel master)`
- `git rebase -i --rebase-merges "$BASE"`

Then edit the todo list to match the actions below:

- Change each “Keep” commit to `reword` (so you can set the new subject).
- Change each “Fixup” commit to `fixup` (drops the commit message, squashes into the previous kept commit).

Suggested todo actions in chronological order:

reword 9994ec81
reword 36f7b22e
fixup  8ad96f97
fixup  31fe5804
fixup  59262185
fixup  3ae6679f
fixup  1931d058
fixup  25849905
fixup  cacacbcf
fixup  68a3dc84
fixup  4ac991f4
fixup  f3e9fb27
fixup  295162ef
fixup  0dbc27c3
fixup  2c0db454
fixup  56978a21
fixup  eeda7ebc
fixup  72844dc0
fixup  7aa26511
fixup  3e9f5ee6
fixup  d70b1eff
reword c18a1219
fixup  fce66966
fixup  af30cccc
fixup  595694bb
fixup  d78183f4
fixup  be1c02bb
reword 3c86b807
fixup  815d01e0
fixup  48db18e6
fixup  a7b2eb94
fixup  c98dffb7
fixup  cbef1b91
reword 0f30d817
fixup  fd6a1899
reword cd43131b
fixup  03cd9f51
fixup  3c799809
reword 3c4b4a50
fixup  69f548ee
fixup  2ba79824
fixup  a38aa8de
fixup  2a495eb3
fixup  7ad4afac
fixup  aaab7da7
fixup  3d53f7d6
fixup  6f450bce
fixup  eab6909f
fixup  037b9ff1
fixup  889dcd7a
fixup  9203dd5a
fixup  617a8651
fixup  e022b663
fixup  1ec64c7e
fixup  d13793b8
fixup  f15dfc04
reword 55569fdf
fixup  8ba785ce
fixup  4bb0ae57
fixup  b30c1559
fixup  c558c152
fixup  d1327f4f
fixup  e33ce8e3
fixup  6c1415b4
fixup  db2dede3
fixup  dc002eac
reword 809bb596
fixup  95a69463
fixup  9c412e72
fixup  704df6bb
fixup  ea769bac
fixup  387d7aaa
fixup  144ad9cf
reword bbc07ca8
fixup  a5971e14
fixup  84e383bf
fixup  9e2fefed
fixup  2296ed99
fixup  44d3193a
fixup  9e57d51b
fixup  959f536d
fixup  52614bdf
fixup  8f70469b
fixup  4d34795e
reword f4166005
fixup  11c95272
reword cf520400
reword 068bf334
fixup  af131b01
reword bed9440e
fixup  83c7b3e1
fixup  567e7c36

If you want fewer commits (≈10–12), the next easiest merges (still no reordering) are:

- Fold metrics into hyperlane by changing `reword cf520400` → `fixup cf520400` (squashes into the `f4166005` commit).
