"""Per-destination privacy and authorization relationships."""

from __future__ import annotations

import unittest
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[2]

OPENROUTER_MODELS = {
    "remote/openrouter/deepseek-v4-flash-0731": "deepseek/deepseek-v4-flash-0731",
    "remote/openrouter/mimo-v2.5": "xiaomi/mimo-v2.5",
    "remote/openrouter/hy3": "tencent/hy3",
    "remote/openrouter/deepseek-v4-flash": "deepseek/deepseek-v4-flash",
    "remote/openrouter/nemotron-3-ultra-free": "nvidia/nemotron-3-ultra-550b-a55b:free",
    "remote/openrouter/gpt-5.6-luna": "openai/gpt-5.6-luna",
    "remote/openrouter/glm-5.2": "z-ai/glm-5.2",
    "remote/openrouter/gemini-3.7-flash": "google/gemini-3.7-flash",
    "remote/openrouter/deepseek-v4-pro-0423": "deepseek/deepseek-v4-pro",
    "remote/openrouter/minimax-m3": "minimax/minimax-m3",
    "remote/openrouter/laguna-s-2.1-free": "poolside/laguna-s-2.1:free",
    "remote/openrouter/claude-opus-5": "anthropic/claude-opus-5",
    "remote/openrouter/gpt-5.6-sol": "openai/gpt-5.6-sol",
    "remote/openrouter/kimi-k3": "moonshotai/kimi-k3",
    "remote/openrouter/claude-sonnet-5": "anthropic/claude-sonnet-5",
    "remote/openrouter/nemotron-3.5-lightning-free": "nvidia/nemotron-3.5-lightning:free",
    "remote/openrouter/deepseek-v4-pro-0813": "deepseek/deepseek-v4-pro-0813",
    "remote/openrouter/gemini-3-flash-preview": "google/gemini-3-flash-preview",
    "remote/openrouter/gemini-2.5-flash-lite": "google/gemini-2.5-flash-lite",
}


def load_yaml(path: str) -> Any:
    """Load one repository-local YAML document."""
    return yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))


def merge_values(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Apply a product values mapping over the shared client values."""
    merged = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = merge_values(merged[key], value)
        else:
            merged[key] = deepcopy(value)
    return merged


def value_paths() -> list[Path]:
    """Return every client-owned values document."""
    paths = [ROOT / "config/client.yaml"]
    paths.extend((ROOT / "apps").glob("**/values.yaml"))
    paths.extend((ROOT / "infrastructure").glob("**/values.yaml"))
    return sorted(paths)


def key_paths(value: Any, path: tuple[str | int, ...] = ()) -> list[tuple[Any, ...]]:
    """Return paths to every mapping key in a parsed values document."""
    paths: list[tuple[Any, ...]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = (*path, key)
            paths.append(child_path)
            paths.extend(key_paths(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            paths.extend(key_paths(child, (*path, index)))
    return paths


class DestinationPolicyTests(unittest.TestCase):
    """Keep each reviewed destination boundary explicit and independently scoped."""

    def setUp(self) -> None:
        self.client = load_yaml("config/client.yaml")
        self.gateway_path = Path(
            "infrastructure/networking/agentgateway/values.yaml"
        )
        self.gateway = load_yaml(str(self.gateway_path))
        self.values = merge_values(self.client, self.gateway)
        self.models = self.values["guardrails"]["llmPolicyEngine"].get(
            "models", []
        )
        self.mcp = self.values["mcp"]
        self.servers = self.mcp.get("servers", [])

    def test_model_catalog_has_exact_destination_policies(self) -> None:
        gateway = load_yaml("infrastructure/networking/agentgateway/values.yaml")
        models = {
            model["name"]: model
            for model in gateway["guardrails"]["llmPolicyEngine"]["models"]
        }
        expected_flags = {
            **{name: (True, True) for name in OPENROUTER_MODELS},
            "local/llama3.2-3b": (False, True),
        }

        self.assertEqual(set(models), set(expected_flags))
        self.assertEqual(
            {
                name: (model["piiEnabled"], model["contentTracingEnabled"])
                for name, model in models.items()
            },
            expected_flags,
        )
        self.assertEqual(
            {name for name, model in models.items() if model.get("piiReroute") is True},
            set(OPENROUTER_MODELS),
        )
        self.assertEqual(
            {name: models[name]["model"] for name in OPENROUTER_MODELS},
            OPENROUTER_MODELS,
        )
        self.assertTrue(
            all(
                models[name]["baseURL"] == "https://openrouter.ai/api/v1"
                and models[name]["provider"] == "Openrouter"
                for name in OPENROUTER_MODELS
            )
        )
        local_ids = {name for name, model in models.items() if model.get("local") is True}
        pii_disabled_ids = {
            name for name, model in models.items() if model["piiEnabled"] is False
        }
        self.assertEqual(local_ids, {"local/llama3.2-3b"})
        self.assertEqual(pii_disabled_ids, local_ids)

    def test_destination_ids_and_privacy_flags_are_explicit(self) -> None:
        catalogs = (("model", self.models), ("MCP server", self.servers))
        for catalog_name, destinations in catalogs:
            self.assertIsInstance(destinations, list)
            ids: list[str] = []
            for destination in destinations:
                with self.subTest(catalog=catalog_name, destination=destination):
                    self.assertIsInstance(destination, dict)
                    destination_id = destination.get("name")
                    self.assertIsInstance(destination_id, str)
                    self.assertTrue(destination_id)
                    ids.append(destination_id)
                    for flag in ("piiEnabled", "contentTracingEnabled"):
                        self.assertIn(flag, destination)
                        self.assertIs(type(destination[flag]), bool)
                    for flag in ("piiReroute", "local"):
                        if flag in destination:
                            self.assertIs(type(destination[flag]), bool)
            self.assertEqual(len(ids), len(set(ids)), f"duplicate {catalog_name} ID")

    def test_mcp_enablement_matches_its_catalog(self) -> None:
        self.assertIs(type(self.mcp.get("enabled")), bool)
        self.assertEqual(self.mcp["enabled"], bool(self.servers))
        if self.models or self.servers:
            self.assertIs(
                self.values["guardrails"]["llmPolicyEngine"].get("enabled"),
                True,
            )

    def test_permissions_are_duplicate_free_catalog_subsets(self) -> None:
        client = load_yaml("config/client.yaml")
        auth = client["authKeycloak"]
        model_ids = {model["name"] for model in self.models}
        mcp_ids = {server["name"] for server in self.servers}
        allowed = {"llm:invoke"}
        allowed.update(f"model:{model_id}:invoke" for model_id in model_ids)
        allowed.update(f"mcp:{server_id}:invoke" for server_id in mcp_ids)

        permission_sets = {
            "agentgatewayClientRoles": auth.get("agentgatewayClientRoles", []),
            "difyAgentgatewayClientRoles": auth.get(
                "difyAgentgatewayClientRoles", []
            ),
        }
        permission_sets.update(auth.get("agentgatewayAccessGroups", {}))

        for owner, permissions in permission_sets.items():
            with self.subTest(owner=owner):
                self.assertIsInstance(permissions, list)
                self.assertTrue(all(isinstance(item, str) for item in permissions))
                self.assertEqual(len(permissions), len(set(permissions)))
                self.assertLessEqual(set(permissions), allowed)

    def test_destination_flags_only_live_in_their_canonical_catalogs(self) -> None:
        flags = {"piiEnabled", "contentTracingEnabled"}
        client_path = Path("config/client.yaml")
        for absolute_path in value_paths():
            relative_path = absolute_path.relative_to(ROOT)
            values = yaml.safe_load(absolute_path.read_text(encoding="utf-8"))
            for path in key_paths(values):
                if path[-1] not in flags:
                    continue
                model_flag = (
                    relative_path == self.gateway_path
                    and path[:3] == ("guardrails", "llmPolicyEngine", "models")
                    and len(path) == 5
                    and isinstance(path[3], int)
                )
                mcp_flag = (
                    relative_path == client_path
                    and path[:2] == ("mcp", "servers")
                    and len(path) == 4
                    and isinstance(path[2], int)
                )
                with self.subTest(path=relative_path, value_path=path):
                    self.assertTrue(model_flag or mcp_flag)

    def test_catalog_authorization_is_exact(self) -> None:
        auth = self.client["authKeycloak"]
        expected = {"llm:invoke"}
        expected.update(f'model:{model["name"]}:invoke' for model in self.models)
        expected.update(f'mcp:{server["name"]}:invoke' for server in self.servers)

        full_access = {
            "agentgatewayClientRoles": auth["agentgatewayClientRoles"],
            **auth["agentgatewayAccessGroups"],
        }
        for owner, permissions in full_access.items():
            with self.subTest(owner=owner):
                self.assertEqual(set(permissions), expected)
                self.assertEqual(len(permissions), len(expected))

        dify_expected = {
            "llm:invoke",
            "model:remote/openrouter/deepseek-v4-flash:invoke",
        }
        dify_roles = auth["difyAgentgatewayClientRoles"]
        self.assertEqual(set(dify_roles), dify_expected)
        self.assertEqual(len(dify_roles), len(dify_expected))
        self.assertLess(set(dify_roles), expected)

    def test_local_models_and_reroutes_have_a_configured_fallback(self) -> None:
        rerouted = [model for model in self.models if model.get("piiReroute") is True]
        local = [model for model in self.models if model.get("local") is True]
        if not rerouted and not local:
            return

        llamacpp = self.values.get("infraAgentgatewayWrapper", {}).get(
            "llamacpp", {}
        )
        self.assertIs(llamacpp.get("enabled"), True)
        self.assertIsInstance(llamacpp.get("host"), str)
        self.assertTrue(llamacpp["host"])

        if rerouted:
            engine = self.values["guardrails"]["llmPolicyEngine"]
            self.assertIs(engine.get("enabled"), True)
            local_target = engine.get("localTarget")
            self.assertIsInstance(local_target, dict)
            self.assertTrue(local_target.get("name"))
            self.assertTrue(local_target.get("model"))
            for model in rerouted:
                with self.subTest(model=model["name"]):
                    self.assertIs(model["piiEnabled"], True)


if __name__ == "__main__":
    unittest.main()
