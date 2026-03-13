# 🐳 docker-mcp

A Model Context Protocol (MCP) server for Docker operations.

## Features

- Create standalone Docker containers
- Deploy Docker Compose stacks
- Retrieve container logs
- List containers
- Deny-first authorization (resource + capability)
- Immutable policy/restriction guardrails
- Authorization audit logging

## Security model

The server enforces two independent authorization layers:

1. Capability policy (what actions are allowed)
2. Resource policy (which containers/images/projects are allowed)

Deny rules always take precedence over allow rules.

## Runtime configuration (path-agnostic)

Set these environment variables when starting the server:

- `DOCKER_MCP_POLICY_FILE` (required)
- `DOCKER_MCP_ACCESS_PROFILE` (required)
- `DOCKER_MCP_DATA_DIR` (optional base dir)
- `DOCKER_MCP_PROTECTED_PATHS` (optional comma-separated absolute paths)
- `DOCKER_MCP_AUTHZ_LOG_FILE` (optional explicit authz log path)

Example:

```bash
export DOCKER_MCP_DATA_DIR="<MCP_DATA_ROOT>/docker-mcp"
export DOCKER_MCP_POLICY_FILE="${DOCKER_MCP_DATA_DIR}/policy.yaml"
export DOCKER_MCP_ACCESS_PROFILE="creator"
export DOCKER_MCP_AUTHZ_LOG_FILE="${DOCKER_MCP_DATA_DIR}/authz.log"
```

## Policy file

Use `examples/policy.yaml` as the baseline schema.

### Deny-first evaluation

For each target (container/image/project):

1. If any deny rule matches -> deny
2. Else if allow list is non-empty and no allow rule matches -> deny
3. Else follow default action

## Guardrails (immutable restrictions)

`docker-mcp` blocks operations that would expose or mount protected policy/restriction paths.

- `create-container`: hook retained for future mutable path inputs.
- `deploy-compose`: rejects compose files that include:
  - bind mounts to protected policy/restriction paths
  - docker socket mounts
  - privileged mode
  - host pid/ipc/network modes

## list-containers behavior

Returns all containers and appends per-row policy metadata:

- `policy_status=ALLOWED|DENIED`
- `policy_reason=...`

## Audit log

Each request writes an authorization decision line to `DOCKER_MCP_AUTHZ_LOG_FILE`.

## Local validation

```bash
UV_CACHE_DIR=/Volumes/Data/_ai/_mcp/mcp-working-cache/_shared/uv uv run python -m compileall src
UV_CACHE_DIR=/Volumes/Data/_ai/_mcp/mcp-working-cache/_shared/uv uv run python tests_policy.py
```

## Local Customization Tracking
- Local machine-specific integration, client wiring, and operational state are tracked under the external data root.
- Local metadata path: `/Volumes/Data/_ai/_mcp/mcp-data/<name>/meta`
- Repo-side capability contract is in `docs/local-capability/`.
- Secrets are never stored in repo docs; only variable names and loading locations are documented.

## Externalized .venv

Repo path ".venv\" is a symlink to canonical cache location under "/Volumes/Data/_ai/_mcp/mcp-working-cache/docker-mcp/.venv\" to reduce repo-local mutable environment state.

## Local Enhancements Capture (2026-03-13)
- Captured current local changes, configuration updates, and operational enhancements for GitHub publication.
- Includes synchronization with sub-repo link updates where applicable.
- Cross-reference local docs and capability notes added in this repository.
