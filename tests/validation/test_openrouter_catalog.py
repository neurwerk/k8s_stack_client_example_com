"""Client-owned OpenRouter catalog contract."""

from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "config/openrouter-catalog-policy.json"
CATALOG = ROOT / "config/openrouter-catalog.yaml"
PRICING = ROOT / "infrastructure/networking/agentgateway/model-pricing.json"
AGENTGATEWAY = ROOT / "infrastructure/networking/agentgateway/values.yaml"
DIFY = ROOT / "apps/dify/values.yaml"
CLIENT = ROOT / "config/client.yaml"


def load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def render(path: str) -> list[dict[str, Any]]:
    output = subprocess.run(
        ["kustomize", "build", "--load-restrictor", "LoadRestrictionsNone", str(ROOT / path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [document for document in yaml.safe_load_all(output) if document]


class OpenRouterCatalogTests(unittest.TestCase):
    def test_generated_catalog_and_pricing_match_policy(self) -> None:
        policy = json.loads(POLICY.read_text(encoding="utf-8"))
        values = load_yaml(CATALOG)
        catalog = values["openrouterCatalog"]
        pricing = json.loads(PRICING.read_text(encoding="utf-8"))["providers"]
        selected = policy["selectedModels"]
        direct_openrouter_pricing = policy["customPricing"].get("openrouter", {})

        self.assertEqual(len(selected), 20)
        self.assertEqual(selected, sorted(set(selected)))
        self.assertEqual([model["upstreamModel"] for model in catalog["models"]], selected)
        self.assertFalse(set(selected) & set(direct_openrouter_pricing))
        self.assertEqual(
            set(pricing["openrouter"]["models"]),
            set(selected) | set(direct_openrouter_pricing),
        )
        self.assertEqual(catalog["grantToAccessGroups"], policy["grantToAccessGroups"])
        self.assertEqual(
            {provider: data["models"] for provider, data in pricing.items() if provider != "openrouter"},
            {
                provider: models
                for provider, models in policy["customPricing"].items()
                if provider != "openrouter"
            },
        )
        self.assertEqual(
            values["infraAgentgatewayWrapper"]["modelCatalog"]["sources"],
            [{"configMap": {"name": "client-model-cost-catalog", "key": "catalog.json"}}],
        )
        client = load_yaml(CLIENT)
        llm_policy = load_yaml(AGENTGATEWAY)["guardrails"]["llmPolicyEngine"]
        direct = llm_policy["models"]
        self.assertEqual(
            {
                model["model"]
                for model in direct
                if model.get("provider") == "Openrouter"
            },
            set(direct_openrouter_pricing),
        )
        effective_names = {model["name"] for model in catalog["models"] + direct}
        default_model = load_yaml(DIFY)["frontendDify"]["defaultModel"]
        self.assertIsInstance(default_model["contextSize"], str)
        self.assertRegex(default_model["contextSize"], r"^[1-9]\d*$")
        dify_models = {default_model["name"]}
        self.assertLessEqual(dify_models, effective_names)
        self.assertTrue(
            {f"model:{model}:invoke" for model in dify_models}.issubset(
                client["authKeycloak"]["difyAgentgatewayClientRoles"]
            )
        )
        routing = client["monitorPiiEngine"]["policy"]["routing"]
        self.assertIn(routing["defaultTarget"], {target["name"] for target in routing["targets"]})
        self.assertLessEqual({target["name"] for target in routing["targets"]}, effective_names)
        local_target = llm_policy["localTarget"]
        self.assertEqual(set(local_target), {"name", "model", "provider", "custom"})
        self.assertEqual(local_target["name"], "llama-cpp")
        self.assertIsInstance(local_target["model"], str)
        self.assertTrue(local_target["model"])
        self.assertEqual(local_target["provider"], "Custom")
        self.assertEqual(local_target["custom"], {"formats": [{"type": "Completions"}]})
        routed_model = next(
            model for model in direct if model["name"] == routing["defaultTarget"]
        )
        self.assertIs(routed_model.get("local"), True)
        self.assertEqual(routed_model["model"], local_target["model"])

    def test_catalog_configmaps_are_composed(self) -> None:
        documents = render("apps") + render("infrastructure")
        maps = {
            (item["metadata"]["name"], item["metadata"]["namespace"]): item["data"]
            for item in documents
            if item.get("kind") == "ConfigMap"
        }
        catalog_data = {"values.yaml": CATALOG.read_text(encoding="utf-8")}
        for namespace in (
            "infra-agentgateway",
            "auth-keycloak",
            "auth-keycloak-api-key-bridge",
            "frontend-librechat",
        ):
            self.assertEqual(maps[("client-openrouter-catalog-values", namespace)], catalog_data)
        self.assertEqual(
            maps[("client-model-cost-catalog", "infra-agentgateway")],
            {"catalog.json": PRICING.read_text(encoding="utf-8")},
        )


if __name__ == "__main__":
    unittest.main()
