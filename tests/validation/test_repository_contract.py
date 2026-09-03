"""Durable client values and Flux composition relationships."""

from __future__ import annotations

import ipaddress
import re
import unittest
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

import yaml


ROOT = Path(__file__).resolve().parents[2]
CLUSTER_PATH = ROOT / "clusters/prod-eu-1"
DNS_NAME = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
SECRET_REFERENCE_KEYS = {
    "authsecret",
    "existingsecret",
    "existingsecretname",
    "secretname",
    "secretref",
}
SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "clientsecret",
    "privatekey",
    "accesskey",
    "apikey",
    "credential",
    "credentials",
    "authtoken",
    "token",
    "secret",
)
CREDENTIAL_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
)


def load_yaml(path: Path) -> Any:
    """Parse one YAML document."""
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_documents(path: Path) -> list[dict[str, Any]]:
    """Parse all resources in a Kubernetes manifest."""
    return [
        document
        for document in yaml.safe_load_all(path.read_text(encoding="utf-8"))
        if document
    ]


def values_paths() -> list[Path]:
    """Return every shared or product values document."""
    paths = [ROOT / "config/client.yaml"]
    paths.extend((ROOT / "apps").glob("**/values.yaml"))
    paths.extend((ROOT / "infrastructure").glob("**/values.yaml"))
    return sorted(paths)


def walk_values(
    value: Any, path: tuple[str | int, ...] = ()
) -> list[tuple[tuple[str | int, ...], Any]]:
    """Return every parsed value with its YAML path."""
    entries: list[tuple[tuple[str | int, ...], Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = (*path, key)
            entries.append((child_path, child))
            entries.extend(walk_values(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_path = (*path, index)
            entries.append((child_path, child))
            entries.extend(walk_values(child, child_path))
    return entries


def nested(values: dict[str, Any], *path: str) -> Any:
    """Read a required nested client value."""
    current: Any = values
    for key in path:
        current = current[key]
    return current


def assignment_target(kustomization_path: Path, generator: dict[str, Any]) -> Path:
    """Resolve a ConfigMap generator's single values.yaml file assignment."""
    files = generator.get("files")
    if not isinstance(files, list) or len(files) != 1:
        raise AssertionError(f"{kustomization_path}: expected one generated file")
    key, separator, source = files[0].partition("=")
    if key != "values.yaml" or separator != "=":
        raise AssertionError(
            f"{kustomization_path}: ConfigMap key must be values.yaml"
        )
    return (kustomization_path.parent / source).resolve()


def is_public_host(host: str) -> bool:
    """Distinguish Internet hosts from cluster-local and loopback URLs."""
    if host == "localhost" or host.endswith((".cluster.local", ".svc")):
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return True


class RepositoryContractTests(unittest.TestCase):
    """Validate ownership and composition without pinning template choices."""

    def test_values_files_are_mappings(self) -> None:
        for path in values_paths():
            with self.subTest(path=path.relative_to(ROOT)):
                values = load_yaml(path)
                self.assertTrue(values is None or isinstance(values, dict))

    def test_librechat_imports_the_canonical_agentgateway_model_values(self) -> None:
        path = ROOT / "apps/librechat/core/kustomization.yaml"
        generators = load_yaml(path)["configMapGenerator"]
        by_name = {generator["name"]: generator for generator in generators}

        self.assertEqual(
            assignment_target(path, by_name["librechat-agentgateway-model-values"]),
            (ROOT / "infrastructure/networking/agentgateway/values.yaml").resolve(),
        )

    def test_leaf_kustomizations_generate_stable_namespace_local_values(self) -> None:
        generated_product_values: set[Path] = set()
        product_values = {
            path.resolve()
            for root in (ROOT / "apps", ROOT / "infrastructure")
            for path in root.glob("**/values.yaml")
        }
        leaves = 0

        for root in (ROOT / "apps", ROOT / "infrastructure"):
            for path in sorted(root.glob("**/kustomization.yaml")):
                kustomization = load_yaml(path)
                generators = kustomization.get("configMapGenerator")
                if generators is None:
                    continue
                leaves += 1
                relative_path = path.relative_to(ROOT)
                with self.subTest(path=relative_path):
                    self.assertIsInstance(kustomization.get("namespace"), str)
                    self.assertTrue(kustomization["namespace"])
                    self.assertIs(
                        kustomization.get("generatorOptions", {}).get(
                            "disableNameSuffixHash"
                        ),
                        True,
                    )
                    names = [generator["name"] for generator in generators]
                    self.assertEqual(len(names), len(set(names)))
                    by_name = {generator["name"]: generator for generator in generators}
                    self.assertIn("client-values", by_name)
                    self.assertEqual(
                        assignment_target(path, by_name["client-values"]),
                        (ROOT / "config/client.yaml").resolve(),
                    )

                    products = [
                        generator
                        for generator in generators
                        if generator["name"].endswith("-product-values")
                    ]
                    self.assertEqual(len(products), 1)
                    target = assignment_target(path, products[0])
                    self.assertIn(target, product_values)
                    self.assertEqual(
                        products[0]["name"], f"{target.parent.name}-product-values"
                    )
                    generated_product_values.add(target)

        self.assertGreater(leaves, 0)
        self.assertEqual(generated_product_values, product_values)

    def test_flux_stages_use_required_sources_order_and_readiness(self) -> None:
        root = load_yaml(CLUSTER_PATH / "kustomization.yaml")
        composed = set(root.get("resources", []))
        direct_manifests = sorted(
            path
            for path in CLUSTER_PATH.glob("*.yaml")
            if path.name != "kustomization.yaml"
        )
        for path in direct_manifests:
            with self.subTest(composed=path.name):
                self.assertIn(path.name, composed)
        self.assertIn("flux-system", composed)

        documents = [
            document
            for path in direct_manifests
            for document in load_documents(path)
        ]
        flux_stages = {
            document["metadata"]["name"]: document
            for document in documents
            if document.get("apiVersion", "").startswith(
                "kustomize.toolkit.fluxcd.io/"
            )
            and document.get("kind") == "Kustomization"
        }
        expected = {
            "namespaces": ("./releases/namespaces", "k8s-stack", set()),
            "client-app-values": ("./apps", "flux-system", {"namespaces"}),
            "client-infrastructure-values": (
                "./infrastructure",
                "flux-system",
                {"namespaces"},
            ),
            "infrastructure": (
                "./releases/infrastructure",
                "k8s-stack",
                {"namespaces", "client-infrastructure-values"},
            ),
            "applications": (
                "./releases/applications",
                "k8s-stack",
                {"infrastructure", "client-app-values"},
            ),
        }

        self.assertLessEqual(set(expected), set(flux_stages))
        for name, (path, source, dependencies) in expected.items():
            with self.subTest(stage=name):
                resource = flux_stages[name]
                spec = resource["spec"]
                self.assertEqual(resource["metadata"].get("namespace"), "flux-system")
                self.assertEqual(spec.get("path"), path)
                self.assertIs(spec.get("prune"), True)
                self.assertTrue(
                    spec.get("wait") is True
                    or bool(spec.get("healthChecks"))
                    or bool(spec.get("healthCheckExprs"))
                )
                self.assertEqual(
                    spec.get("sourceRef"),
                    {
                        "kind": "GitRepository",
                        "name": source,
                        "namespace": "flux-system",
                    },
                )
                dependency_entries = spec.get("dependsOn", [])
                self.assertEqual(
                    len(dependency_entries),
                    len({item["name"] for item in dependency_entries}),
                )
                self.assertEqual(
                    {item["name"] for item in dependency_entries},
                    dependencies,
                )

        flux_documents = documents + load_documents(
            CLUSTER_PATH / "flux-system/gotk-sync.yaml"
        )
        for resource in flux_documents:
            if resource.get("kind") != "Kustomization":
                continue
            with self.subTest(resource=resource.get("metadata", {}).get("name")):
                self.assertNotIn("decryption", resource.get("spec", {}))

    def test_k3s_monitoring_and_gateway_readiness_are_safe(self) -> None:
        monitoring = load_yaml(
            ROOT
            / "infrastructure/observability/kube-prometheus-stack/values.yaml"
        )["kube-prometheus-stack"]
        for component in ("kubeControllerManager", "kubeScheduler", "kubeProxy"):
            with self.subTest(component=component):
                self.assertIs(monitoring[component]["enabled"], False)

        gateway_expressions = 0
        for path in sorted(CLUSTER_PATH.glob("*.yaml")):
            for resource in load_documents(path):
                if resource.get("kind") != "Kustomization":
                    continue
                expressions = resource.get("spec", {}).get("healthCheckExprs", [])
                identities = [
                    (expression.get("apiVersion"), expression.get("kind"))
                    for expression in expressions
                ]
                self.assertEqual(len(identities), len(set(identities)))
                for expression in expressions:
                    if expression.get("kind") != "Gateway":
                        continue
                    gateway_expressions += 1
                    for state in ("current", "inProgress", "failed"):
                        condition = expression.get(state, "")
                        self.assertIn("observedGeneration", condition)
                        self.assertIn("metadata.generation", condition)
                    self.assertIn("Programmed", expression["current"])
                    self.assertIn("ResolvedRefs", expression["current"])
                    self.assertIn("InvalidCertificateRef", expression["inProgress"])
                    self.assertIn("RefNotPermitted", expression["failed"])

        self.assertGreater(gateway_expressions, 0)

    def test_cluster_identity_matches_the_client_source(self) -> None:
        identity = load_yaml(CLUSTER_PATH / "cluster-identity.yaml")
        self.assertEqual(identity.get("apiVersion"), "v1")
        self.assertEqual(identity.get("kind"), "ConfigMap")
        self.assertEqual(identity.get("metadata", {}).get("namespace"), "flux-system")
        data = identity.get("data", {})
        self.assertEqual(
            set(data), {"schemaVersion", "client", "environment", "clusterId"}
        )
        self.assertRegex(data["schemaVersion"], r"^[1-9]\d*$")
        self.assertRegex(data["client"], r"^[a-z0-9]+(?:_[a-z0-9]+)*$")
        self.assertRegex(data["environment"], r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
        self.assertEqual(str(UUID(data["clusterId"])), data["clusterId"])

        private_sources = [
            document
            for document in load_documents(
                CLUSTER_PATH / "flux-system/gotk-sync.yaml"
            )
            if document.get("kind") == "GitRepository"
        ]
        self.assertEqual(len(private_sources), 1)
        repository = Path(urlsplit(private_sources[0]["spec"]["url"]).path).stem
        prefix = "k8s_stack_"
        self.assertTrue(repository.startswith(prefix))
        self.assertEqual(data["client"], repository.removeprefix(prefix))

    def test_public_urls_and_oidc_hosts_are_coherent(self) -> None:
        client = load_yaml(ROOT / "config/client.yaml")
        auth = client["authKeycloak"]
        host_relationships = {
            "librechatRedirectUri": nested(client, "frontendLibrechat", "hostname"),
            "librechatWebOrigin": nested(client, "frontendLibrechat", "hostname"),
            "librechatAdminRedirectUri": nested(
                client, "frontendLibrechat", "hostname"
            ),
            "librechatAdminWebOrigin": nested(
                client, "frontendLibrechat", "adminPanel", "hostname"
            ),
            "agentgatewayRedirectUri": nested(
                client, "infraAgentgatewayWrapper", "hostname"
            ),
            "agentgatewayWebOrigin": nested(
                client, "infraAgentgatewayWrapper", "hostname"
            ),
            "studioRedirectUri": nested(
                client, "frontendStudio", "studio", "hostname"
            ),
            "studioWebOrigin": nested(
                client, "frontendStudio", "studio", "hostname"
            ),
            "keycloakApiKeyBridgeRedirectUri": nested(
                client, "authKeycloakApiKeyBridge", "hostname"
            ),
            "keycloakApiKeyBridgeWebOrigin": nested(
                client, "authKeycloakApiKeyBridge", "hostname"
            ),
            "difyRedirectUri": nested(client, "frontendDify", "hostname"),
            "difyWebOrigin": nested(client, "frontendDify", "hostname"),
        }

        for key, host in host_relationships.items():
            with self.subTest(setting=key):
                self.assertIsInstance(host, str)
                self.assertRegex(host, DNS_NAME)
                configured = auth.get(key)
                if not configured:
                    continue
                parsed = urlsplit(configured)
                self.assertEqual(parsed.scheme, "https")
                self.assertEqual(parsed.hostname, host)
                self.assertNotIn("*", configured)
                self.assertIsNone(parsed.username)
                self.assertIsNone(parsed.password)
                if key.endswith("WebOrigin"):
                    self.assertEqual(configured, f"https://{host}")

        for path in values_paths():
            values = load_yaml(path)
            for value_path, value in walk_values(values):
                if not isinstance(value, str) or not value.startswith(
                    ("http://", "https://")
                ):
                    continue
                parsed = urlsplit(value)
                if not parsed.hostname or not is_public_host(parsed.hostname):
                    continue
                with self.subTest(path=path.relative_to(ROOT), value_path=value_path):
                    self.assertEqual(parsed.scheme, "https")
                    self.assertNotIn("*", value)
                    self.assertIsNone(parsed.username)
                    self.assertIsNone(parsed.password)

    def test_certificate_selection_has_one_client_owner(self) -> None:
        client_path = ROOT / "config/client.yaml"
        client = load_yaml(client_path)
        certificates = client.get("publicCertificates")
        self.assertIsInstance(certificates, dict)
        self.assertEqual(set(certificates), {"useProduction"})
        self.assertIs(type(certificates["useProduction"]), bool)

        uses: list[tuple[Path, tuple[str | int, ...]]] = []
        for path in values_paths():
            values = load_yaml(path)
            for value_path, _ in walk_values(values):
                if value_path[-1] == "useProduction":
                    uses.append((path, value_path))
                if path != client_path and value_path[-1] == "clusterIssuer":
                    self.fail(f"{path.relative_to(ROOT)} duplicates clusterIssuer")
        self.assertEqual(uses, [(client_path, ("publicCertificates", "useProduction"))])

    def test_values_contain_references_but_not_credentials(self) -> None:
        for path in values_paths():
            values = load_yaml(path)
            for value_path, value in walk_values(values):
                string_path = tuple(str(part) for part in value_path)
                normalized_key = re.sub(r"[^a-z0-9]", "", string_path[-1].lower())
                inside_patterns = "patterns" in string_path
                with self.subTest(path=path.relative_to(ROOT), value_path=value_path):
                    if any(
                        normalized_key == part or normalized_key.endswith(part)
                        for part in SENSITIVE_KEY_PARTS
                    ):
                        if normalized_key in SECRET_REFERENCE_KEYS or normalized_key.endswith(
                            ("secretref", "secretname")
                        ):
                            self.assertIsInstance(value, str)
                            self.assertRegex(
                                value, r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$"
                            )
                        else:
                            self.assertIn(value, (None, ""))

                    if not isinstance(value, str) or inside_patterns:
                        continue
                    self.assertFalse(
                        any(pattern.search(value) for pattern in CREDENTIAL_PATTERNS)
                    )
                    parsed = urlsplit(value)
                    if parsed.scheme and parsed.hostname:
                        self.assertIsNone(parsed.username)
                        self.assertIsNone(parsed.password)


if __name__ == "__main__":
    unittest.main()
