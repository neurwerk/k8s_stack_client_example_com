"""Focused security checks for client-owned values."""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml


ROOT = Path(__file__).resolve().parents[2]
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


def values_paths() -> list[Path]:
    paths = [ROOT / "config/client.yaml"]
    paths.extend((ROOT / "apps").glob("**/values.yaml"))
    paths.extend((ROOT / "infrastructure").glob("**/values.yaml"))
    return sorted(paths)


def walk_values(
    value: Any, path: tuple[str | int, ...] = ()
) -> list[tuple[tuple[str | int, ...], Any]]:
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


class RepositoryContractTests(unittest.TestCase):
    def test_client_does_not_own_secrets_or_platform_releases(self) -> None:
        forbidden = {
            "ClusterExternalSecret",
            "ClusterSecretStore",
            "ExternalSecret",
            "HelmRelease",
            "SealedSecret",
            "Secret",
            "SecretStore",
        }
        for root in ("apps", "infrastructure", "clusters"):
            for path in (ROOT / root).glob("**/*.yaml"):
                text = path.read_text(encoding="utf-8")
                with self.subTest(path=path.relative_to(ROOT)):
                    self.assertNotRegex(
                        text, r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"
                    )
                    for document in yaml.safe_load_all(text):
                        if not isinstance(document, dict):
                            continue
                        self.assertNotIn(document.get("kind"), forbidden)
                        self.assertNotIn("secretGenerator", document)
                        self.assertNotIn("decryption", document.get("spec", {}))

    def test_values_do_not_embed_credentials_or_unsafe_public_urls(self) -> None:
        for path in values_paths():
            values = yaml.safe_load(path.read_text(encoding="utf-8"))
            self.assertTrue(values is None or isinstance(values, dict))
            for value_path, value in walk_values(values):
                normalized_key = re.sub(
                    r"[^a-z0-9]", "", str(value_path[-1]).lower()
                )
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

                    if not isinstance(value, str) or "patterns" in value_path:
                        continue
                    self.assertFalse(
                        any(pattern.search(value) for pattern in CREDENTIAL_PATTERNS)
                    )
                    parsed = urlsplit(value)
                    if not parsed.scheme or not parsed.hostname:
                        continue
                    self.assertIsNone(parsed.username)
                    self.assertIsNone(parsed.password)
                    if not parsed.hostname.endswith((".cluster.local", ".svc")):
                        self.assertEqual(parsed.scheme, "https")


if __name__ == "__main__":
    unittest.main()
