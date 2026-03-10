from __future__ import annotations

from pathlib import Path
from typing import Any
import os


class GuardrailError(Exception):
    """Raised when immutable restriction guardrails are violated."""


class Guardrails:
    def __init__(self, policy_file: Path, data_dir: Path):
        self.policy_file = policy_file.resolve()
        self.data_dir = data_dir.resolve()
        self.protected = self._build_protected_paths()

    @classmethod
    def from_env(cls, policy_file: Path) -> "Guardrails":
        raw_data = os.environ.get("DOCKER_MCP_DATA_DIR")
        if raw_data:
            data_dir = Path(raw_data).expanduser().resolve()
        else:
            data_dir = (Path.home() / ".local" / "share" / "docker-mcp").resolve()
        return cls(policy_file=policy_file, data_dir=data_dir)

    def _build_protected_paths(self) -> set[Path]:
        protected: set[Path] = {self.policy_file, self.data_dir}

        if self.data_dir.exists() and self.data_dir.is_dir():
            for path in self.data_dir.rglob("*"):
                if not path.is_file():
                    continue
                name = path.name.lower()
                if ("policy" in name or "restriction" in name) and name.endswith((".yml", ".yaml", ".json", ".toml", ".conf")):
                    protected.add(path.resolve())

        raw = os.environ.get("DOCKER_MCP_PROTECTED_PATHS", "").strip()
        if raw:
            for entry in raw.split(","):
                item = entry.strip()
                if not item:
                    continue
                protected.add(Path(item).expanduser().resolve())

        return protected

    def _is_protected(self, candidate: Path) -> bool:
        c = candidate.resolve()
        for p in self.protected:
            try:
                if c == p or c.is_relative_to(p):
                    return True
            except ValueError:
                continue
        return False

    def _extract_bind_source(self, vol: Any) -> Path | None:
        # Compose short syntax: /host:/container[:mode]
        if isinstance(vol, str):
            parts = vol.split(":")
            if not parts:
                return None
            source = parts[0]
            if source.startswith("/"):
                return Path(source)
            return None

        # Compose long syntax
        if isinstance(vol, dict):
            vtype = str(vol.get("type", "")).strip().lower()
            if vtype and vtype != "bind":
                return None
            source = vol.get("source") or vol.get("src")
            if isinstance(source, str) and source.startswith("/"):
                return Path(source)
        return None

    def validate_create(self, arguments: dict[str, Any]) -> None:
        violations: list[str] = []

        if bool(arguments.get("privileged", False)):
            violations.append("create-container: privileged=true is blocked")

        for host_mode_key in ("pid", "ipc", "network_mode"):
            val = str(arguments.get(host_mode_key, "")).strip().lower()
            if val == "host":
                violations.append(f"create-container: {host_mode_key}=host is blocked")

        # Defensive checks even if current tool schema does not expose these fields.
        volumes = arguments.get("volumes", [])
        if isinstance(volumes, list):
            for vol in volumes:
                source = self._extract_bind_source(vol)
                if source is None:
                    continue
                if str(source) == "/var/run/docker.sock":
                    violations.append("create-container: docker socket mount is blocked")
                if self._is_protected(source):
                    violations.append(f"create-container: bind mount to protected path blocked: {source}")

        if violations:
            raise GuardrailError("; ".join(violations))

    def validate_compose(self, compose_obj: dict[str, Any]) -> None:
        services = compose_obj.get("services", {})
        if not isinstance(services, dict):
            raise GuardrailError("compose services must be an object")

        violations: list[str] = []

        for svc_name, svc_def in services.items():
            if not isinstance(svc_def, dict):
                continue

            if bool(svc_def.get("privileged", False)):
                violations.append(f"service {svc_name}: privileged=true is blocked")

            for host_mode_key in ("pid", "ipc", "network_mode"):
                val = str(svc_def.get(host_mode_key, "")).strip().lower()
                if val == "host":
                    violations.append(f"service {svc_name}: {host_mode_key}=host is blocked")

            volumes = svc_def.get("volumes", [])
            if isinstance(volumes, list):
                for vol in volumes:
                    source = self._extract_bind_source(vol)
                    if source is None:
                        continue
                    if str(source) == "/var/run/docker.sock":
                        violations.append(f"service {svc_name}: docker socket mount is blocked")
                    if self._is_protected(source):
                        violations.append(f"service {svc_name}: bind mount to protected path blocked: {source}")

        if violations:
            raise GuardrailError("; ".join(violations))
