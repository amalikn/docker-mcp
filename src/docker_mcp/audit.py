from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import json
import os


def _default_authz_log_file() -> Path:
    raw = os.environ.get("DOCKER_MCP_AUTHZ_LOG_FILE", "").strip()
    if raw:
        return Path(raw).expanduser().resolve()

    data_dir = os.environ.get("DOCKER_MCP_DATA_DIR", "").strip()
    if data_dir:
        return (Path(data_dir).expanduser().resolve() / "authz.log")

    return (Path.home() / ".local" / "share" / "docker-mcp" / "authz.log").resolve()


def audit_log(entry: dict) -> None:
    path = _default_authz_log_file()
    path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "ts": datetime.now(tz=timezone.utc).isoformat(),
        **entry,
    }

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, sort_keys=True))
        f.write("\n")
