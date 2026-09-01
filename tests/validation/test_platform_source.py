"""Platform release source contract."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

import yaml

from scripts.check_platform_compatibility import (
    CLUSTER_KUSTOMIZATION_PATH,
    CLUSTER_RESOURCES,
    FLUX_KUSTOMIZATION_PATH,
    FLUX_RESOURCES,
    FLUX_SYNC_PATH,
    PLATFORM_SOURCE_PATH,
    parse_flux_sync,
    parse_kustomization,
    parse_platform_source,
)

ROOT = Path(__file__).resolve().parents[2]
SEMVER_TAG = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


class PlatformSourceTest(unittest.TestCase):
    def test_platform_uses_one_exact_verified_release_tag(self) -> None:
        content = (ROOT / PLATFORM_SOURCE_PATH).read_text()
        source = yaml.safe_load(content)
        spec = source["spec"]
        annotations = source["metadata"]["annotations"]

        self.assertEqual(
            parse_platform_source(content, origin=str(PLATFORM_SOURCE_PATH)),
            (spec["ref"]["tag"], annotations["platform.neurwerk.com/adoption-mode"]),
        )
        self.assertEqual(spec["url"], "https://github.com/neurwerk/k8s_stack_base.git")
        self.assertNotIn("secretRef", spec)
        self.assertEqual(set(spec["ref"]), {"tag"})
        self.assertRegex(spec["ref"]["tag"], SEMVER_TAG)
        self.assertEqual(
            annotations.get("platform.neurwerk.com/adoption-target"),
            spec["ref"]["tag"],
        )
        self.assertIn(
            annotations.get("platform.neurwerk.com/adoption-mode"),
            {"fresh-install", "upgrade"},
        )
        self.assertEqual(spec["verify"].get("mode"), "Tag")
        trust_secret = spec["verify"].get("secretRef", {}).get("name")
        self.assertEqual(trust_secret, "k8s-stack-release-trust")

    def test_platform_composition_controls_are_transform_free(self) -> None:
        parse_kustomization(
            (ROOT / CLUSTER_KUSTOMIZATION_PATH).read_text(),
            origin=str(CLUSTER_KUSTOMIZATION_PATH),
            resources=CLUSTER_RESOURCES,
        )
        parse_kustomization(
            (ROOT / FLUX_KUSTOMIZATION_PATH).read_text(),
            origin=str(FLUX_KUSTOMIZATION_PATH),
            resources=FLUX_RESOURCES,
        )
        parse_flux_sync((ROOT / FLUX_SYNC_PATH).read_text(), origin=str(FLUX_SYNC_PATH))


if __name__ == "__main__":
    unittest.main()
