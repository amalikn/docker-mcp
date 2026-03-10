from __future__ import annotations

from typing import List, Dict, Any
import asyncio
import os
import platform
import yaml
from python_on_whales import DockerClient
from mcp.types import TextContent

from .docker_executor import DockerComposeExecutor
from .authz import AuthzEngine, TargetContext
from .policy import PolicyError
from .guardrails import Guardrails, GuardrailError
from .audit import audit_log


docker_client = DockerClient()
AUTHZ: AuthzEngine | None = None
GUARDRAILS: Guardrails | None = None


def init_authorization() -> None:
    """Initialize policy/capability runtime once at server startup."""
    global AUTHZ, GUARDRAILS
    authz = AuthzEngine.from_env()
    guardrails = Guardrails.from_env(authz.policy_path())
    AUTHZ = authz
    GUARDRAILS = guardrails


def _require_runtime() -> tuple[AuthzEngine, Guardrails]:
    if AUTHZ is None or GUARDRAILS is None:
        raise PolicyError(
            "Authorization runtime not initialized. "
            "Set DOCKER_MCP_POLICY_FILE and DOCKER_MCP_ACCESS_PROFILE, then call init_authorization()."
        )
    return AUTHZ, GUARDRAILS


def _safe_container_image(container: Any) -> str:
    try:
        image = getattr(container, "image", None)
        if image is None:
            return ""
        # python-on-whales may expose image as object; str() gives a usable reference.
        return str(image)
    except Exception:  # noqa: BLE001
        return ""


async def parse_port_mapping(host_key: str, container_port: str | int) -> tuple[str, str] | tuple[str, str, str]:
    if "/" in str(host_key):
        host_port, protocol = host_key.split("/")
        if protocol.lower() == "udp":
            return (str(host_port), str(container_port), "udp")
        return (str(host_port), str(container_port))

    if isinstance(container_port, str) and "/" in container_port:
        port, protocol = container_port.split("/")
        if protocol.lower() == "udp":
            return (str(host_key), port, "udp")
        return (str(host_key), port)

    return (str(host_key), str(container_port))


class DockerHandlers:
    TIMEOUT_AMOUNT = 200

    @staticmethod
    def _deny_text(reason: str) -> List[TextContent]:
        return [TextContent(type="text", text=f"Denied by policy: {reason} | policy_block=true")]

    @staticmethod
    def _log(
        tool: str,
        ctx: TargetContext,
        allowed: bool,
        reason: str,
        result_code: int | None = None,
        capability: str = "",
    ) -> None:
        authz, _ = _require_runtime()
        audit_log(
            {
                "tool": tool,
                "profile": authz.profile_name,
                "capability": capability,
                "container_name": ctx.container_name,
                "image": ctx.image,
                "project_name": ctx.project_name,
                "allowed": allowed,
                "reason": reason,
                "result_code": result_code,
            }
        )

    @staticmethod
    async def handle_create_container(arguments: Dict[str, Any]) -> List[TextContent]:
        authz, guardrails = _require_runtime()
        ctx = TargetContext(
            tool_name="create-container",
            container_name=str(arguments.get("name", "")),
            image=str(arguments.get("image", "")),
        )
        decision = authz.authorize(ctx)
        if not decision.allowed:
            DockerHandlers._log(ctx.tool_name, ctx, False, decision.reason, capability=decision.capability_required)
            return DockerHandlers._deny_text(decision.reason)

        try:
            image = arguments["image"]
            container_name = arguments.get("name")
            ports = arguments.get("ports", {})
            environment = arguments.get("environment", {})

            if not image:
                raise ValueError("Image name cannot be empty")

            guardrails.validate_create(arguments)

            port_mappings = []
            for host_key, container_port in ports.items():
                mapping = await parse_port_mapping(host_key, container_port)
                port_mappings.append(mapping)

            async def pull_and_run():
                if not docker_client.image.exists(image):
                    await asyncio.to_thread(docker_client.image.pull, image)

                container = await asyncio.to_thread(
                    docker_client.container.run,
                    image,
                    name=container_name,
                    publish=port_mappings,
                    envs=environment,
                    detach=True,
                )
                return container

            container = await asyncio.wait_for(pull_and_run(), timeout=DockerHandlers.TIMEOUT_AMOUNT)
            DockerHandlers._log(ctx.tool_name, ctx, True, "created", 0, capability=decision.capability_required)
            return [TextContent(type="text", text=f"Created container '{container.name}' (ID: {container.id})")]
        except GuardrailError as exc:
            DockerHandlers._log(ctx.tool_name, ctx, False, str(exc), capability=decision.capability_required)
            return DockerHandlers._deny_text(str(exc))
        except asyncio.TimeoutError:
            DockerHandlers._log(ctx.tool_name, ctx, False, "timeout", capability=decision.capability_required)
            return [TextContent(type="text", text=f"Operation timed out after {DockerHandlers.TIMEOUT_AMOUNT} seconds")]
        except Exception as exc:  # noqa: BLE001
            DockerHandlers._log(ctx.tool_name, ctx, False, str(exc), 1, capability=decision.capability_required)
            return [TextContent(type="text", text=f"Error creating container: {exc} | Arguments: {arguments}")]

    @staticmethod
    async def handle_deploy_compose(arguments: Dict[str, Any]) -> List[TextContent]:
        authz, guardrails = _require_runtime()
        debug_info: list[str] = []
        project_name = str(arguments.get("project_name", ""))
        compose_yaml = arguments.get("compose_yaml")
        ctx_project = TargetContext(tool_name="deploy-compose", project_name=project_name)

        project_decision = authz.authorize(ctx_project)
        if not project_decision.allowed:
            DockerHandlers._log(
                ctx_project.tool_name,
                ctx_project,
                False,
                project_decision.reason,
                capability=project_decision.capability_required,
            )
            return DockerHandlers._deny_text(project_decision.reason)

        try:
            if not compose_yaml or not project_name:
                raise ValueError("Missing required compose_yaml or project_name")

            yaml_content = DockerHandlers._process_yaml(compose_yaml, debug_info)
            guardrails.validate_compose(yaml_content)

            # Pre-flight image authorization before deployment.
            services = yaml_content.get("services", {})
            if isinstance(services, dict):
                for service_name, service_obj in services.items():
                    if not isinstance(service_obj, dict):
                        continue
                    service_image = str(service_obj.get("image", ""))
                    if not service_image:
                        continue
                    ctx_image = TargetContext(
                        tool_name="deploy-compose",
                        project_name=project_name,
                        image=service_image,
                    )
                    image_decision = authz.authorize(ctx_image)
                    if not image_decision.allowed:
                        reason = f"service '{service_name}' blocked: {image_decision.reason}"
                        DockerHandlers._log(
                            ctx_image.tool_name,
                            ctx_image,
                            False,
                            reason,
                            capability=image_decision.capability_required,
                        )
                        return DockerHandlers._deny_text(reason)

            compose_path = DockerHandlers._save_compose_file(yaml_content, project_name)
            try:
                result = await DockerHandlers._deploy_stack(compose_path, project_name, debug_info)
                DockerHandlers._log(
                    ctx_project.tool_name,
                    ctx_project,
                    True,
                    "deployed",
                    0,
                    capability=project_decision.capability_required,
                )
                return [TextContent(type="text", text=result)]
            finally:
                DockerHandlers._cleanup_files(compose_path)
        except GuardrailError as exc:
            DockerHandlers._log(
                ctx_project.tool_name,
                ctx_project,
                False,
                str(exc),
                capability=project_decision.capability_required,
            )
            return DockerHandlers._deny_text(str(exc))
        except Exception as exc:  # noqa: BLE001
            debug_output = "\n".join(debug_info)
            DockerHandlers._log(
                ctx_project.tool_name,
                ctx_project,
                False,
                str(exc),
                1,
                capability=project_decision.capability_required,
            )
            return [TextContent(type="text", text=f"Error deploying compose stack: {exc}\n\nDebug Information:\n{debug_output}")]

    @staticmethod
    def _process_yaml(compose_yaml: str, debug_info: List[str]) -> dict:
        debug_info.append("=== Original YAML ===")
        debug_info.append(compose_yaml)

        try:
            yaml_content = yaml.safe_load(compose_yaml)
            if not isinstance(yaml_content, dict):
                raise ValueError("Compose YAML root must be an object")
            debug_info.append("\n=== Loaded YAML Structure ===")
            debug_info.append(str(yaml_content))
            return yaml_content
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML format: {exc}") from exc

    @staticmethod
    def _save_compose_file(yaml_content: dict, project_name: str) -> str:
        compose_dir = os.path.join(os.getcwd(), "docker_compose_files")
        os.makedirs(compose_dir, exist_ok=True)

        compose_yaml = yaml.safe_dump(yaml_content, default_flow_style=False, sort_keys=False)
        compose_path = os.path.join(compose_dir, f"{project_name}-docker-compose.yml")

        with open(compose_path, "w", encoding="utf-8") as f:
            f.write(compose_yaml)
            f.flush()
            if platform.system() != "Windows":
                os.fsync(f.fileno())

        return compose_path

    @staticmethod
    async def _deploy_stack(compose_path: str, project_name: str, debug_info: List[str]) -> str:
        compose = DockerComposeExecutor(compose_path, project_name)

        for command in [compose.down, compose.up]:
            try:
                code, out, err = await command()
                debug_info.extend(
                    [
                        f"\n=== {command.__name__.capitalize()} Command ===",
                        f"Return Code: {code}",
                        f"Stdout: {out}",
                        f"Stderr: {err}",
                    ]
                )
                if code != 0 and command == compose.up:
                    raise RuntimeError(f"Deploy failed with code {code}: {err}")
            except Exception as exc:  # noqa: BLE001
                if command != compose.down:
                    raise
                debug_info.append(f"Warning during {command.__name__}: {exc}")

        code, out, _err = await compose.ps()
        service_info = out if code == 0 else "Unable to list services"
        return (
            f"Successfully deployed compose stack '{project_name}'\n"
            f"Running services:\n{service_info}\n\n"
            f"Debug Info:\n{chr(10).join(debug_info)}"
        )

    @staticmethod
    def _cleanup_files(compose_path: str) -> None:
        try:
            if os.path.exists(compose_path):
                os.remove(compose_path)
            compose_dir = os.path.dirname(compose_path)
            if os.path.exists(compose_dir) and not os.listdir(compose_dir):
                os.rmdir(compose_dir)
        except Exception as exc:  # noqa: BLE001
            print(f"Warning during cleanup: {exc}")

    @staticmethod
    async def handle_get_logs(arguments: Dict[str, Any]) -> List[TextContent]:
        authz, _ = _require_runtime()
        debug_info: list[str] = []
        container_name = str(arguments.get("container_name", ""))
        ctx = TargetContext(tool_name="get-logs", container_name=container_name)
        decision = authz.authorize(ctx)
        if not decision.allowed:
            DockerHandlers._log(ctx.tool_name, ctx, False, decision.reason, capability=decision.capability_required)
            return DockerHandlers._deny_text(decision.reason)

        try:
            if not container_name:
                raise ValueError("Missing required container_name")

            debug_info.append(f"Fetching logs for container '{container_name}'")
            logs = await asyncio.to_thread(docker_client.container.logs, container_name, tail=100)
            DockerHandlers._log(ctx.tool_name, ctx, True, "logs_fetched", 0, capability=decision.capability_required)
            return [TextContent(type="text", text=f"Logs for container '{container_name}':\n{logs}\n\nDebug Info:\n{chr(10).join(debug_info)}")]
        except Exception as exc:  # noqa: BLE001
            debug_output = "\n".join(debug_info)
            DockerHandlers._log(ctx.tool_name, ctx, False, str(exc), 1, capability=decision.capability_required)
            return [TextContent(type="text", text=f"Error retrieving logs: {exc}\n\nDebug Information:\n{debug_output}")]

    @staticmethod
    async def handle_list_containers(arguments: Dict[str, Any]) -> List[TextContent]:
        authz, _ = _require_runtime()
        _ = arguments
        debug_info: list[str] = []
        cap_ctx = TargetContext(tool_name="list-containers")
        cap_decision = authz.authorize(cap_ctx)
        if not cap_decision.allowed:
            DockerHandlers._log(
                cap_ctx.tool_name,
                cap_ctx,
                False,
                cap_decision.reason,
                capability=cap_decision.capability_required,
            )
            return DockerHandlers._deny_text(cap_decision.reason)

        try:
            debug_info.append("Listing all Docker containers")
            containers = await asyncio.to_thread(docker_client.container.list, all=True)
            rows: list[str] = []

            for c in containers:
                name = getattr(c, "name", "")
                image = _safe_container_image(c)
                status = getattr(getattr(c, "state", None), "status", "unknown")
                ctx = TargetContext(tool_name="list-containers", container_name=str(name), image=image)
                try:
                    decision = authz.authorize(ctx)
                    policy_status = "ALLOWED" if decision.allowed else "DENIED"
                    reason = "allowed" if decision.allowed else decision.reason
                except Exception as exc:  # noqa: BLE001
                    policy_status = "UNKNOWN"
                    reason = f"policy evaluation error: {exc}"
                rows.append(
                    f"{str(getattr(c, 'id', ''))[:12]} - {name} - {status} - "
                    f"policy_status={policy_status} - policy_reason={reason}"
                )

            DockerHandlers._log(
                cap_ctx.tool_name,
                cap_ctx,
                True,
                "list_generated",
                0,
                capability=cap_decision.capability_required,
            )
            return [TextContent(type="text", text=f"All Docker Containers:\n{chr(10).join(rows)}\n\nDebug Info:\n{chr(10).join(debug_info)}")]
        except Exception as exc:  # noqa: BLE001
            debug_output = "\n".join(debug_info)
            DockerHandlers._log(
                cap_ctx.tool_name,
                cap_ctx,
                False,
                str(exc),
                1,
                capability=cap_decision.capability_required,
            )
            return [TextContent(type="text", text=f"Error listing containers: {exc}\n\nDebug Information:\n{debug_output}")]
