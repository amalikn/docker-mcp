from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os

from .policy import (
    Policy,
    PolicyError,
    evaluate_rules,
    load_policy,
    normalize_image,
    normalize_name,
    normalize_project,
)


VALID_CAPABILITIES = {"observe", "create", "modify", "exec", "destroy", "admin"}
TOOL_CAPABILITY = {
    "list-containers": "observe",
    "get-logs": "observe",
    "create-container": "create",
    "deploy-compose": "create",
}


@dataclass(frozen=True)
class TargetContext:
    tool_name: str
    container_name: str = ""
    image: str = ""
    project_name: str = ""


@dataclass(frozen=True)
class Decision:
    allowed: bool
    capability_required: str
    reason: str


class AuthzEngine:
    def __init__(self, policy: Policy, profile_name: str):
        self.policy = policy
        self.profile_name = profile_name
        if profile_name not in policy.profiles:
            raise PolicyError(f"Unknown access profile: {profile_name}")

        caps = policy.profiles[profile_name]
        unknown = caps - VALID_CAPABILITIES
        if unknown:
            raise PolicyError(f"Profile {profile_name} has unknown capabilities: {sorted(unknown)}")

    @classmethod
    def from_env(cls) -> "AuthzEngine":
        policy = load_policy()
        profile_name = os.environ.get("DOCKER_MCP_ACCESS_PROFILE", "").strip()
        if not profile_name:
            raise PolicyError("DOCKER_MCP_ACCESS_PROFILE must be set")
        return cls(policy, profile_name)

    def policy_path(self) -> Path:
        raw = os.environ.get("DOCKER_MCP_POLICY_FILE")
        if raw:
            return Path(raw).expanduser().resolve()
        from .policy import default_policy_file

        return default_policy_file()

    def capability_for_tool(self, tool_name: str) -> str:
        return TOOL_CAPABILITY.get(tool_name, "")

    def _check_capability(self, tool_name: str) -> tuple[bool, str, str]:
        required = self.capability_for_tool(tool_name)
        if not required:
            return False, "", f"unknown tool capability mapping for {tool_name}"
        if required not in self.policy.profiles[self.profile_name]:
            return False, required, f"capability '{required}' not granted to profile '{self.profile_name}'"
        return True, required, "capability granted"

    def _check_resources(self, ctx: TargetContext) -> tuple[bool, str]:
        if not self.policy.enabled:
            return True, "policy disabled"

        if ctx.container_name:
            allowed, reason = evaluate_rules(
                normalize_name(ctx.container_name),
                self.policy.containers,
                self.policy.match_mode,
                self.policy.default_action,
            )
            if not allowed:
                return False, f"container '{ctx.container_name}' denied: {reason}"

        if ctx.image:
            allowed, reason = evaluate_rules(
                normalize_image(ctx.image),
                self.policy.images,
                self.policy.match_mode,
                self.policy.default_action,
            )
            if not allowed:
                return False, f"image '{ctx.image}' denied: {reason}"

        if ctx.project_name:
            allowed, reason = evaluate_rules(
                normalize_project(ctx.project_name),
                self.policy.projects,
                self.policy.match_mode,
                self.policy.default_action,
            )
            if not allowed:
                return False, f"project '{ctx.project_name}' denied: {reason}"

        return True, "resource policy allowed"

    def authorize(self, ctx: TargetContext) -> Decision:
        ok, required, reason = self._check_capability(ctx.tool_name)
        if not ok:
            return Decision(False, required, reason)

        ok, rreason = self._check_resources(ctx)
        if not ok:
            return Decision(False, required, rreason)

        return Decision(True, required, "allowed")
