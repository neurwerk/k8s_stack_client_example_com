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
        self.values = merge_values(self.client, gateway)
        self.models = self.values["guardrails"]["llmPolicyEngine"].get(
            "models", []
        )
        self.servers = self.values["mcp"].get("servers", [])

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
        permission_sets = {
            "agentgatewayClientRoles": auth.get("agentgatewayClientRoles", []),
            **auth.get("agentgatewayAccessGroups", {}),
        }

        for owner, permissions in permission_sets.items():
            with self.subTest(owner=owner):
                self.assertTrue(all(isinstance(item, str) for item in permissions))
                self.assertEqual(len(permissions), len(set(permissions)))
                self.assertLessEqual(set(permissions), allowed)

    def test_privacy_reroutes_have_a_local_fallback(self) -> None:
        rerouted = [model for model in self.models if model.get("piiReroute") is True]
        if not rerouted:
            return

        engine = self.values["guardrails"]["llmPolicyEngine"]
        local_target = engine.get("localTarget")
        self.assertIs(engine.get("enabled"), True)
        self.assertIsInstance(local_target, dict)
        self.assertTrue(local_target.get("name"))
        self.assertTrue(local_target.get("model"))
        self.assertIs(
            self.values.get("infraAgentgatewayWrapper", {})
            .get("llamacpp", {})
            .get("enabled"),
            True,
        )
        for model in rerouted:
            with self.subTest(model=model["name"]):
                self.assertIs(model.get("piiEnabled"), True)


if __name__ == "__main__":
    unittest.main()
