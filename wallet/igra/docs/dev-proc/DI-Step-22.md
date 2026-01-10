# Domain/Infrastructure Refactor – Step 22 (Foundation/Domain kickoff)

## Plan
- Begin delineating the foundation vs domain layers: identify shared primitives (types, errors, utilities, constants) that should live under `foundation/` and ensure domain modules depend only on foundation/domain, not infra.
- Document scope and next actions before code moves.

## Notes (pre-work)
- Foundation tree already exists; next steps will be to map current `util`, `constants`, and shared types into `foundation` and update imports accordingly while keeping shims for compatibility.
- No code changes in this step; this is the kickoff record for the foundation/domain separation work.
