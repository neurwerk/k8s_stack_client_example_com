"""Security invariants for model and MCP destinations."""

from __future__ import annotations

import unittest
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[2]


def load_yaml(path: str) -> Any:
    return yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))


def merge_values(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = merge_values(merged[key], value)
        else:
            merged[key] = deepcopy(value)
    return merged


class DestinationPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = load_yaml("config/client.yaml")
        gateway = load_yaml("infrastructure/networking/agentgateway/values.yaml")
        self.values = merge_values(
            merge_values(load_yaml("config/openrouter-catalog.yaml"), self.client), gateway
        )
        explicit = self.values["guardrails"]["llmPolicyEngine"].get("models", [])
        catalog = self.values.get("openrouterCatalog", {})
        entries = catalog.get("models", []) if catalog.get("enabled") else []
        for definitions in (explicit, entries):
            ids = [model["name"] for model in definitions]
            self.assertEqual(len(ids), len(set(ids)), "duplicate catalog definition")
        # Product entries intentionally override matching OpenRouter catalog entries.
        definitions = {model["name"]: model for model in entries}
        definitions.update({model["name"]: model for model in explicit})
        self.bindings = [
            binding
            for group in (
                "self-hosted-api-providers",
                "external-api-providers",
                "external-subscription-providers",
            )
            for binding in self.values.get(group, [])
            if binding.get("enabled") is True
        ]
        self.models = []
        for binding in self.bindings:
            for name in binding.get("catalogModels", []):
                self.assertIn(name, definitions, "binding references an unknown model")
                self.models.append(definitions[name])
            self.models.extend(binding.get("models", []))
        mcp = self.values.get("mcp-servers", {})
        self.servers = []
        if mcp.get("enabled") is True:
            self.servers.extend(
                {**server, "name": name}
                for name, server in mcp.get("catalog", {}).get("presets", {}).items()
                if server.get("enabled") is True
            )
            self.servers.extend(
                server for server in mcp.get("catalog", {}).get("custom", [])
                if server.get("enabled") is True
            )

    def test_destinations_have_unique_ids_and_explicit_privacy_policy(self) -> None:
        for catalog_name, destinations in (
            ("model", self.models),
            ("MCP server", self.servers),
        ):
            ids: list[str] = []
            for destination in destinations:
                with self.subTest(catalog=catalog_name, destination=destination):
                    destination_id = destination.get("name")
                    self.assertIsInstance(destination_id, str)
                    self.assertTrue(destination_id)
                    ids.append(destination_id)
                    for flag in ("piiEnabled", "contentTracingEnabled"):
                        self.assertIs(type(destination.get(flag)), bool)
            self.assertEqual(len(ids), len(set(ids)), f"duplicate {catalog_name} ID")

    def test_permissions_are_duplicate_free_catalog_subsets(self) -> None:
        auth = self.client["authKeycloak"]
        allowed = {"llm:invoke"}
        allowed.update(f'model:{model["name"]}:invoke' for model in self.models)
        allowed.update(f'mcp:{server["name"]}:invoke' for server in self.servers)
        allowed.update(
            f'provider:{binding["providerId"]}:global-use'
            for binding in self.bindings
            if "global" in binding.get("credentialSources", [])
        )
        permission_sets = {
            "agentgatewayClientRoles": auth.get("agentgatewayClientRoles", []),
            "difyAgentgatewayClientRoles": auth.get("difyAgentgatewayClientRoles", []),
            **auth.get("agentgatewayAccessGroups", {}),
        }
        for path in (ROOT / "apps").glob("**/*approval/values.yaml"):
            values = load_yaml(str(path.relative_to(ROOT)))
            for section in ("clientApproval", "serviceApproval", "authentication"):
                if section in values:
                    permission_sets[f"{path.relative_to(ROOT)}:{section}"] = values[
                        section
                    ].get("gatewayPermissions", [])

        for owner, permissions in permission_sets.items():
            with self.subTest(owner=owner):
                self.assertTrue(all(isinstance(item, str) for item in permissions))
                self.assertEqual(len(permissions), len(set(permissions)))
                self.assertLessEqual(set(permissions), allowed)

    def test_privacy_reroutes_have_a_local_fallback(self) -> None:
        rerouted = [binding for binding in self.bindings if binding.get("localReroute")]
        if not rerouted:
            return

        engine = self.values["guardrails"]["llmPolicyEngine"]
        self.assertIs(engine.get("enabled"), True)
        local_targets = {
            name
            for binding in self.values.get("self-hosted-api-providers", [])
            if binding.get("enabled") is True
            and binding.get("credentialSources") == ["none"]
            for name in binding.get("catalogModels", [])
        }
        models = {model["name"]: model for model in self.models}
        for binding in rerouted:
            with self.subTest(binding=binding["id"]):
                target = binding["localReroute"]
                self.assertIn(target, local_targets)
                self.assertIn(target, models)
                self.assertIs(models[target].get("local"), True)
                for name in binding.get("catalogModels", []):
                    self.assertIs(models[name].get("piiEnabled"), True)


if __name__ == "__main__":
    unittest.main()
