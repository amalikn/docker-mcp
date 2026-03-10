# Approved Plan: Harden docker-mcp with Deny-First Resource + Capability Authorization + Immutable Restriction Guardrails

Status: approved
Date: 2026-03-11
Channel: codex-main
Tag: docker-mcp

## Summary

- Implement two independent policy layers in docker-mcp:
  1. Capability policy (what action class is allowed)
  2. Resource policy (what container/image/project targets are allowed)
- Enforce deny-list precedence over allow-list.
- Add hard guardrails so docker-mcp can never be used to modify its own `policy.yml` or related restriction files.
- Keep implementation path-agnostic via placeholders/env vars.

## Implementation Changes

### 1. Plan artifact governance (March 6 decision compliance)

- On execution start, persist approved plan as:
  - `${DOCKER_MCP_REPO_DIR}/plan/YYYYMMDD_HHMM_docker_mcp_hardening_approved.md`
- Non-approved variants must be saved with `_deferred.md` suffix.
- Maintain index in `${DOCKER_MCP_REPO_DIR}/plan/README.md` with status (`approved|deferred`).

### 2. Policy and profile model

- New env/config placeholders:
  - `DOCKER_MCP_POLICY_FILE` (required)
  - `DOCKER_MCP_DATA_DIR` (base for logs/restrictions)
  - `DOCKER_MCP_ACCESS_PROFILE` (required)
  - `DOCKER_MCP_AUTHZ_LOG_FILE` (default `${DOCKER_MCP_DATA_DIR}/authz.log`)
  - `DOCKER_MCP_PROTECTED_PATHS` (optional extra protected paths)
- Policy YAML schema:
  - `enabled`, `default_action`, `match_mode: [exact, glob]`
  - `resources.containers|images|projects.allow|deny`
  - `profiles.<name>.capabilities`
- Capability set:
  - `observe`, `create`, `modify`, `exec`, `destroy`, `admin`
- Required tool mapping (current repo):
  - `list-containers -> observe`
  - `get-logs -> observe`
  - `create-container -> create`
  - `deploy-compose -> create`
- Authorization order:
  1. profile + capability check
  2. resource policy check (deny first)
  3. execute

### 3. Immutable restriction guardrails

- Startup-resolved protected set includes:
  - `${DOCKER_MCP_POLICY_FILE}`
  - all restriction artifacts under `${DOCKER_MCP_DATA_DIR}` (for example: `*policy*.yml`, `*restriction*.yml`)
  - optional entries from `DOCKER_MCP_PROTECTED_PATHS`
- Guardrails enforced before Docker execution:
  - `create-container`: reject if request implies protected path access or breakout primitives
  - `deploy-compose`: parse compose YAML and reject protected path references or breakout primitives (`privileged`, docker socket mount, host `pid`/`ipc`/`network_mode`)
- Guardrails are server-side only and not argument-overridable.

### 4. List behavior and observability

- `list-containers` returns all containers and appends:
  - `policy_status=ALLOWED|DENIED|UNKNOWN`
  - `policy_reason=...`
- Structured authz audit log per call with:
  - timestamp, tool, profile, capability, resource inputs, allow/deny, reason, Docker result.

### 5. Code structure (decision-complete)

- Modules:
  - `policy.py` (load/validate rules, normalize targets, deny-first evaluation)
  - `authz.py` (tool->capability mapping, profile checks, combined decision)
  - `guardrails.py` (protected-path and breakout checks)
  - `audit.py` (authz log writer)
- `handlers.py`:
  - build target context per tool call
  - call `authorize(...)` before action
  - preserve existing tool interfaces
- `README.md`:
  - policy schema, profile examples, env placeholders, deny precedence, immutable guardrails.

## Test Plan

- Deny precedence: allow+deny match => denied.
- Allow-list enforcement: non-empty allow with no match => denied.
- Capability enforcement: profile lacks required capability => denied.
- Immutable guardrails:
  - policy/restriction path mount/reference => denied.
  - privileged breakout patterns in compose/create => denied.
- List output: all containers returned with expected `policy_status` and reason.
- Fail-closed checks:
  - missing/invalid policy/profile => startup failure in hardened mode.
  - unknown tool/capability => denied by default.

## Assumptions / Defaults

- Hardened mode is fail-closed for mutating operations.
- `exec` remains separate from `modify`.
- One docker-mcp process per profile remains the operational model.
- No add-ons included in v1 beyond this scope.
