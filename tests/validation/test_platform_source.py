"""Platform release source contract."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
SEMVER_TAG = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


class PlatformSourceTest(unittest.TestCase):
    def test_platform_uses_one_exact_verified_release_tag(self) -> None:
        source = yaml.safe_load(
            (ROOT / "clusters/prod-eu-1/platform-source.yaml").read_text()
        )
        spec = source["spec"]

        self.assertEqual(spec["url"], "https://github.com/neurwerk/k8s_stack_base.git")
        self.assertNotIn("secretRef", spec)
        self.assertEqual(set(spec["ref"]), {"tag"})
        self.assertRegex(spec["ref"]["tag"], SEMVER_TAG)
        self.assertEqual(spec["verify"].get("mode"), "Tag")
        trust_secret = spec["verify"].get("secretRef", {}).get("name")
        self.assertIsInstance(trust_secret, str)
        self.assertTrue(trust_secret)


if __name__ == "__main__":
    unittest.main()
