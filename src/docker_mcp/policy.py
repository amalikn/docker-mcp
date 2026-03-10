from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any
import os

import yaml


class PolicyError(Exception):
    """Raised when policy loading/validation fails."""


@dataclass(frozen=True)
class RuleSet:
    allow: list[str]
    deny: list[str]


@dataclass(frozen=True)
class Policy:
    enabled: bool
    default_action: str
    match_mode: set[str]
    containers: RuleSet
    images: RuleSet
    projects: RuleSet
    profiles: dict[str, set[str]]


def default_data_dir() -> Path:
    raw = os.environ.get("DOCKER_MCP_DATA_DIR")
    if raw:
        return Path(raw).expanduser().resolve()
    return (Path.home() / ".local" / "share" / "docker-mcp").resolve()


def default_policy_file() -> Path:
    raw = os.environ.get("DOCKER_MCP_POLICY_FILE")
    if raw:
        return Path(raw).expanduser().resolve()
    return (default_data_dir() / "policy.yaml").resolve()


def _ensure_list(data: Any, field: str) -> list[str]:
    if data is None:
        return []
    if not isinstance(data, list):
        raise PolicyError(f"{field} must be a list of strings")
    out: list[str] = []
    for i, item in enumerate(data):
        if not isinstance(item, str) or not item.strip():
            raise PolicyError(f"{field}[{i}] must be a non-empty string")
        out.append(item.strip())
    return out


def _extract_rules(root: dict[str, Any], key: str) -> RuleSet:
    resources = root.get("resources")
    if not isinstance(resources, dict):
        raise PolicyError("resources must be an object")
    target = resources.get(key, {})
    if not isinstance(target, dict):
        raise PolicyError(f"resources.{key} must be an object")
    return RuleSet(
        allow=_ensure_list(target.get("allow", []), f"resources.{key}.allow"),
        deny=_ensure_list(target.get("deny", []), f"resources.{key}.deny"),
    )


def _extract_profiles(root: dict[str, Any]) -> dict[str, set[str]]:
    profiles = root.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise PolicyError("profiles must be a non-empty object")

    out: dict[str, set[str]] = {}
    for profile_name, profile_obj in profiles.items():
        if not isinstance(profile_name, str) or not profile_name.strip():
            raise PolicyError("profiles keys must be non-empty strings")
        if not isinstance(profile_obj, dict):
            raise PolicyError(f"profiles.{profile_name} must be an object")
        caps = _ensure_list(profile_obj.get("capabilities", []), f"profiles.{profile_name}.capabilities")
        if not caps:
            raise PolicyError(f"profiles.{profile_name}.capabilities must not be empty")
        out[profile_name] = set(caps)
    return out


def load_policy(policy_file: Path | None = None) -> Policy:
    path = (policy_file or default_policy_file()).expanduser().resolve()
    if not path.exists():
        raise PolicyError(f"Policy file not found: {path}")

    try:
        root = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise PolicyError(f"Failed to parse policy file {path}: {exc}") from exc

    if not isinstance(root, dict):
        raise PolicyError("Policy root must be an object")

    enabled = bool(root.get("enabled", True))
    default_action = str(root.get("default_action", "allow")).strip().lower()
    if default_action not in {"allow", "deny"}:
        raise PolicyError("default_action must be 'allow' or 'deny'")

    match_mode_raw = root.get("match_mode", ["exact", "glob"])
    match_mode_list = _ensure_list(match_mode_raw, "match_mode")
    match_mode = {x.lower() for x in match_mode_list}
    if not match_mode.issubset({"exact", "glob"}) or not match_mode:
        raise PolicyError("match_mode entries must be exact and/or glob")

    return Policy(
        enabled=enabled,
        default_action=default_action,
        match_mode=match_mode,
        containers=_extract_rules(root, "containers"),
        images=_extract_rules(root, "images"),
        projects=_extract_rules(root, "projects"),
        profiles=_extract_profiles(root),
    )


def normalize_name(name: str | None) -> str:
    return (name or "").strip().lower()


def normalize_project(project: str | None) -> str:
    return (project or "").strip().lower()


def normalize_image(image: str | None) -> str:
    img = (image or "").strip().lower()
    if not img:
        return ""

    if "@" in img:
        # Leave digest references as-is.
        return img

    if "/" not in img:
        img = f"docker.io/library/{img}"
    elif img.count("/") == 1 and not img.split("/")[0].startswith(("docker.io", "ghcr.io", "quay.io")):
        first = img.split("/")[0]
        if "." not in first and ":" not in first and first != "localhost":
            img = f"docker.io/{img}"

    last = img.split("/")[-1]
    if ":" not in last:
        img = f"{img}:latest"

    return img


def _matches(value: str, pattern: str, mode: set[str]) -> bool:
    if not value:
        return False
    if "exact" in mode and value == pattern.lower():
        return True
    if "glob" in mode and fnmatchcase(value, pattern.lower()):
        return True
    return False


def evaluate_rules(value: str, rules: RuleSet, mode: set[str], default_action: str) -> tuple[bool, str]:
    for pat in rules.deny:
        if _matches(value, pat, mode):
            return False, f"matched deny rule: {pat}"

    if rules.allow:
        for pat in rules.allow:
            if _matches(value, pat, mode):
                return True, "matched allow rule"
        return False, "not in allow list"

    return (default_action == "allow"), f"default_action={default_action}"
