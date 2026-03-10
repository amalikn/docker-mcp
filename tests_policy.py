from pathlib import Path
import tempfile
import textwrap
import unittest

from docker_mcp.policy import load_policy, evaluate_rules, RuleSet
from docker_mcp.authz import AuthzEngine, TargetContext
from docker_mcp.guardrails import Guardrails, GuardrailError


class PolicyTests(unittest.TestCase):
    def test_deny_overrides_allow(self):
        rules = RuleSet(allow=["lab-*"], deny=["lab-danger"])
        allowed, reason = evaluate_rules("lab-danger", rules, {"exact", "glob"}, "allow")
        self.assertFalse(allowed)
        self.assertIn("deny", reason)

    def test_allow_nonempty_requires_match(self):
        rules = RuleSet(allow=["lab-*"], deny=[])
        allowed, reason = evaluate_rules("prod-1", rules, {"exact", "glob"}, "allow")
        self.assertFalse(allowed)
        self.assertIn("allow", reason)

    def test_capability_check(self):
        with tempfile.TemporaryDirectory() as td:
            policy_file = Path(td) / "policy.yaml"
            policy_file.write_text(
                textwrap.dedent(
                    """
                    enabled: true
                    default_action: allow
                    match_mode: [exact, glob]
                    resources:
                      containers: {allow: [], deny: []}
                      images: {allow: [], deny: []}
                      projects: {allow: [], deny: []}
                    profiles:
                      creator:
                        capabilities: [observe, create]
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            policy = load_policy(policy_file)
            engine = AuthzEngine(policy=policy, profile_name="creator")
            d1 = engine.authorize(TargetContext(tool_name="create-container", image="nginx"))
            d2 = engine.authorize(TargetContext(tool_name="deploy-compose", project_name="x"))
            d3 = engine.authorize(TargetContext(tool_name="unknown-tool"))
            self.assertTrue(d1.allowed)
            self.assertTrue(d2.allowed)
            self.assertFalse(d3.allowed)

    def test_guardrails_block_protected_and_breakout_patterns(self):
        with tempfile.TemporaryDirectory() as td:
            data_dir = Path(td) / "data"
            data_dir.mkdir(parents=True, exist_ok=True)
            policy_file = data_dir / "policy.yaml"
            policy_file.write_text("enabled: true\nresources: {containers: {}, images: {}, projects: {}}\nprofiles: {x: {capabilities: [observe]}}\n", encoding="utf-8")

            g = Guardrails(policy_file=policy_file, data_dir=data_dir)

            with self.assertRaises(GuardrailError):
                g.validate_create(
                    {
                        "privileged": True,
                        "volumes": [f"{policy_file}:/tmp/policy.yaml:ro"],
                    }
                )

            with self.assertRaises(GuardrailError):
                g.validate_compose(
                    {
                        "services": {
                            "svc": {
                                "image": "nginx:latest",
                                "network_mode": "host",
                                "volumes": ["/var/run/docker.sock:/var/run/docker.sock"],
                            }
                        }
                    }
                )


if __name__ == "__main__":
    unittest.main()
