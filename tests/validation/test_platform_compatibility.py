"""Offline tests for the trusted platform release compatibility gate."""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

import yaml

from scripts.check_platform_compatibility import (
    FRESH_INSTALL_LABEL,
    CompatibilityError,
    fetch_pull_request_head,
    parse_platform_source,
    parse_recovery_contract,
    parse_support_contract,
    parse_tag,
    run_check,
    validate_release_contract,
)

ROOT = Path(__file__).resolve().parents[2]
FINGERPRINT = "SHA256:+rDcofrsfRE3ElJJxnUVoB3gmoEzZJUrisDqLZMHimw"


def source(tag: str, *, trust_secret: str = "k8s-stack-release-trust") -> str:
    return yaml.safe_dump(
        {
            "spec": {
                "url": "https://github.com/neurwerk/k8s_stack_base.git",
                "ref": {"tag": tag},
                "verify": {
                    "mode": "Tag",
                    "secretRef": {"name": trust_secret},
                },
            }
        }
    )


def manifest(
    tag: str,
    *,
    upgrades_from: list[str],
    fresh_install: str = "supported",
    downgrade: str = "unsupported",
    recovery: str = "replacement-restore",
) -> str:
    return yaml.safe_dump(
        {
            "apiVersion": "platform.neurwerk.com/v1alpha1",
            "kind": "PlatformRelease",
            "metadata": {"name": tag},
            "spec": {
                "version": tag.removeprefix("v"),
                "trust": {
                    "algorithm": "ssh-ed25519",
                    "fingerprint": FINGERPRINT,
                },
                "compatibility": {
                    "freshInstall": fresh_install,
                    "upgradesFrom": upgrades_from,
                    "downgrade": downgrade,
                    "recovery": recovery,
                },
            },
        }
    )


def migration(
    tag: str,
    *,
    old_tags: list[str] | None = None,
    downgrade: str = "Unsupported",
    recovery: str = "Replacement restore",
) -> str:
    old_tags = old_tags or []
    supported = (
        ", ".join(f"`{old_tag}`" for old_tag in old_tags) if old_tags else "None"
    )
    sections = {
        "Support": (
            "- Fresh installation: Supported.\n"
            f"- Supported source versions: {supported}.\n"
            f"- Downgrade: {downgrade}."
        ),
        "Prerequisites": "None.",
        "Client Actions": "None.",
        "Stateful And API Effects": "None.",
        "Pre-Deployment Checks": "None.",
        "Post-Deployment Checks": "None.",
        "Recovery": f"Recovery classification: {recovery}.",
        "Exclusions": "None.",
    }
    body = "\n\n".join(f"## {heading}\n\n{text}" for heading, text in sections.items())
    return f"# Platform {tag}\n\n{body}\n"


def release(tag: str, **overrides: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "tag_name": tag,
        "draft": False,
        "prerelease": False,
        "published_at": "2026-01-01T00:00:00Z",
    }
    result.update(overrides)
    return result


class PlatformCompatibilityTests(unittest.TestCase):
    def test_strict_tags_reject_ranges_and_prereleases(self) -> None:
        self.assertEqual(parse_tag("v1.2.3", field="tag"), (1, 2, 3))
        for invalid in ("1.2.3", "v1.2", "v1.2.3-rc.1", "v01.2.3", ">=v1.2.3"):
            with self.subTest(tag=invalid), self.assertRaises(CompatibilityError):
                parse_tag(invalid, field="tag")

    def test_platform_source_requires_the_exact_trust_secret(self) -> None:
        self.assertEqual(parse_platform_source(source("v1.2.3"), origin="test"), "v1.2.3")
        with self.assertRaisesRegex(CompatibilityError, "k8s-stack-release-trust"):
            parse_platform_source(
                source("v1.2.3", trust_secret="another-trust-root"), origin="test"
            )

    def test_explicit_upgrade_path_is_accepted(self) -> None:
        validate_release_contract(
            "v0.2.0",
            "v0.2.1",
            manifest("v0.2.1", upgrades_from=["v0.2.0"]),
            migration("v0.2.1", old_tags=["v0.2.0"]),
            release("v0.2.1"),
            set(),
            FINGERPRINT,
        )

    def test_migration_source_set_must_exactly_equal_manifest(self) -> None:
        with self.assertRaisesRegex(CompatibilityError, "exactly equal"):
            validate_release_contract(
                "v0.2.0",
                "v0.2.2",
                manifest("v0.2.2", upgrades_from=["v0.2.0", "v0.2.1"]),
                migration("v0.2.2", old_tags=["v0.2.0"]),
                release("v0.2.2"),
                set(),
                FINGERPRINT,
            )

    def test_wrapped_source_versions_are_parsed_and_compared_exactly(self) -> None:
        sources = ["v0.2.0", "v0.2.1", "v0.2.2", "v0.2.3", "v0.2.4"]
        migration_text = migration("v0.2.5", old_tags=sources).replace(
            "- Supported source versions: "
            "`v0.2.0`, `v0.2.1`, `v0.2.2`, `v0.2.3`, `v0.2.4`.",
            "- Supported source versions: "
            "`v0.2.0`, `v0.2.1`, `v0.2.2`, `v0.2.3`,\n  `v0.2.4`.",
        )
        validate_release_contract(
            "v0.2.4",
            "v0.2.5",
            manifest(
                "v0.2.5",
                upgrades_from=[source.removeprefix("v") for source in sources],
            ),
            migration_text,
            release("v0.2.5"),
            set(),
            FINGERPRINT,
        )
        with self.assertRaisesRegex(CompatibilityError, "exactly equal"):
            validate_release_contract(
                "v0.2.4",
                "v0.2.5",
                manifest(
                    "v0.2.5",
                    upgrades_from=[source.removeprefix("v") for source in sources[:-1]],
                ),
                migration_text,
                release("v0.2.5"),
                set(),
                FINGERPRINT,
            )

    def test_malformed_source_version_continuations_are_rejected(self) -> None:
        cases = {
            "missing comma before wrap": (
                "- Supported source versions: `v0.2.0`\n  `v0.2.1`."
            ),
            "one-space indent": (
                "- Supported source versions: `v0.2.0`,\n `v0.2.1`."
            ),
            "three-space indent": (
                "- Supported source versions: `v0.2.0`,\n   `v0.2.1`."
            ),
            "unknown continuation": (
                "- Supported source versions: `v0.2.0`,\n  and later releases."
            ),
            "continuation after period": (
                "- Supported source versions: `v0.2.0`.\n  `v0.2.1`."
            ),
            "missing final period": (
                "- Supported source versions: `v0.2.0`,\n  `v0.2.1`,"
            ),
        }
        for name, declaration in cases.items():
            support = (
                "- Fresh installation: Supported.\n"
                f"{declaration}\n"
                "- Downgrade: Unsupported."
            )
            with self.subTest(name=name), self.assertRaisesRegex(
                CompatibilityError, "Supported source versions"
            ):
                parse_support_contract(support)

    def test_legacy_bare_manifest_sources_are_target_bounded(self) -> None:
        for target, old_tag in (("v0.2.1", "v0.2.0"), ("v0.2.5", "v0.2.4")):
            with self.subTest(target=target):
                validate_release_contract(
                    old_tag,
                    target,
                    manifest(target, upgrades_from=[old_tag.removeprefix("v")]),
                    migration(target, old_tags=[old_tag]),
                    release(target),
                    set(),
                    FINGERPRINT,
                )

        for target, old_tag in (
            ("v0.2.0", "v0.1.0"),
            ("v0.2.6", "v0.2.5"),
            ("v1.0.0", "v0.2.5"),
        ):
            with self.subTest(target=target), self.assertRaisesRegex(
                CompatibilityError, "legacy bare SemVer outside affected targets"
            ):
                validate_release_contract(
                    old_tag,
                    target,
                    manifest(target, upgrades_from=[old_tag.removeprefix("v")]),
                    migration(target, old_tags=[old_tag]),
                    release(target),
                    set(),
                    FINGERPRINT,
                )

    def test_legacy_manifest_normalization_remains_strict_and_unique(self) -> None:
        for invalid in ("01.2.3", "0.2", "0.2.3-rc.1", ">=0.2.0"):
            with self.subTest(value=invalid), self.assertRaisesRegex(
                CompatibilityError, "exact strict vX.Y.Z"
            ):
                validate_release_contract(
                    "v0.2.0",
                    "v0.2.5",
                    manifest("v0.2.5", upgrades_from=[invalid]),
                    migration("v0.2.5", old_tags=["v0.2.0"]),
                    release("v0.2.5"),
                    set(),
                    FINGERPRINT,
                )
        with self.assertRaisesRegex(CompatibilityError, "contains duplicates"):
            validate_release_contract(
                "v0.2.0",
                "v0.2.2",
                manifest("v0.2.2", upgrades_from=["0.2.0", "v0.2.0"]),
                migration("v0.2.2", old_tags=["v0.2.0"]),
                release("v0.2.2"),
                set(),
                FINGERPRINT,
            )

    def test_known_downgrade_and_recovery_values_are_normalized(self) -> None:
        support = (
            "- Fresh installation: Supported.\n"
            "- Supported source versions: None.\n"
            "- Downgrade: Supported."
        )
        self.assertEqual(
            parse_support_contract(support), ("supported", set(), "supported")
        )
        recovery_values = {
            "Configuration revert": "configuration-revert",
            "Forward fix": "forward-fix",
            "Component native restore": "component-native-restore",
            "Replacement restore": "replacement-restore",
        }
        for display, normalized in recovery_values.items():
            with self.subTest(display=display):
                self.assertEqual(
                    parse_recovery_contract(f"Recovery classification: {display}."),
                    normalized,
                )

    def test_downgrade_declaration_is_exact_and_agrees_with_manifest(self) -> None:
        valid = migration("v0.2.1", old_tags=["v0.2.0"])
        cases = {
            "missing": (
                valid.replace("- Downgrade: Unsupported.\n", ""),
                "exactly one downgrade",
            ),
            "duplicate": (
                valid.replace(
                    "- Downgrade: Unsupported.",
                    "- Downgrade: Unsupported.\n- Downgrade: Unsupported.",
                ),
                "exactly one downgrade",
            ),
            "unknown": (
                valid.replace("- Downgrade: Unsupported.", "- Downgrade: Conditional."),
                "must be Supported or Unsupported",
            ),
            "mismatch": (
                migration("v0.2.1", old_tags=["v0.2.0"], downgrade="Supported"),
                "disagrees with the manifest",
            ),
        }
        for name, (migration_text, error) in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(
                CompatibilityError, error
            ):
                validate_release_contract(
                    "v0.2.0",
                    "v0.2.1",
                    manifest("v0.2.1", upgrades_from=["v0.2.0"]),
                    migration_text,
                    release("v0.2.1"),
                    set(),
                    FINGERPRINT,
                )
        with self.assertRaisesRegex(CompatibilityError, "manifest downgrade"):
            validate_release_contract(
                "v0.2.0",
                "v0.2.1",
                manifest(
                    "v0.2.1", upgrades_from=["v0.2.0"], downgrade="conditional"
                ),
                valid,
                release("v0.2.1"),
                set(),
                FINGERPRINT,
            )

    def test_recovery_declaration_is_exact_and_agrees_with_manifest(self) -> None:
        valid = migration("v0.2.1", old_tags=["v0.2.0"])
        declaration = "Recovery classification: Replacement restore."
        cases = {
            "missing": (
                valid.replace(declaration, "No recovery classification declared."),
                "exactly one recovery classification",
            ),
            "duplicate": (
                valid.replace(declaration, f"{declaration}\n{declaration}"),
                "exactly one recovery classification",
            ),
            "unknown": (
                valid.replace(declaration, "Recovery classification: Snapshot restore."),
                "must be one of",
            ),
            "mismatch": (
                migration(
                    "v0.2.1", old_tags=["v0.2.0"], recovery="Forward fix"
                ),
                "disagrees with the manifest",
            ),
        }
        for name, (migration_text, error) in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(
                CompatibilityError, error
            ):
                validate_release_contract(
                    "v0.2.0",
                    "v0.2.1",
                    manifest("v0.2.1", upgrades_from=["v0.2.0"]),
                    migration_text,
                    release("v0.2.1"),
                    set(),
                    FINGERPRINT,
                )
        with self.assertRaisesRegex(CompatibilityError, "manifest recovery"):
            validate_release_contract(
                "v0.2.0",
                "v0.2.1",
                manifest("v0.2.1", upgrades_from=["v0.2.0"], recovery="snapshot"),
                valid,
                release("v0.2.1"),
                set(),
                FINGERPRINT,
            )
        misleading = migration("v0.2.1").replace(
            "## Prerequisites", "The prose mentions `v0.2.0`.\n\n## Prerequisites"
        )
        with self.assertRaisesRegex(CompatibilityError, "exactly equal"):
            validate_release_contract(
                "v0.2.0",
                "v0.2.1",
                manifest("v0.2.1", upgrades_from=["v0.2.0"]),
                misleading,
                release("v0.2.1"),
                set(),
                FINGERPRINT,
            )

    def test_fresh_install_label_is_required_but_described_as_intent(self) -> None:
        arguments = (
            "v0.2.0",
            "v0.2.1",
            manifest("v0.2.1", upgrades_from=[]),
            migration("v0.2.1"),
            release("v0.2.1"),
        )
        with self.assertRaisesRegex(CompatibilityError, "not authorization"):
            validate_release_contract(*arguments, set(), FINGERPRINT)
        validate_release_contract(*arguments, {FRESH_INSTALL_LABEL}, FINGERPRINT)

    def test_downgrade_and_unpublished_release_are_rejected(self) -> None:
        with self.assertRaisesRegex(CompatibilityError, "downgrade"):
            validate_release_contract(
                "v0.2.1",
                "v0.2.0",
                manifest("v0.2.0", upgrades_from=["v0.2.1"]),
                migration("v0.2.0", old_tags=["v0.2.1"]),
                release("v0.2.0"),
                set(),
                FINGERPRINT,
            )
        with self.assertRaisesRegex(CompatibilityError, "published"):
            validate_release_contract(
                "v0.2.0",
                "v0.2.1",
                manifest("v0.2.1", upgrades_from=["v0.2.0"]),
                migration("v0.2.1", old_tags=["v0.2.0"]),
                release("v0.2.1", draft=True),
                set(),
                FINGERPRINT,
            )

    def test_manifest_agreement_and_migration_headings_are_required(self) -> None:
        invalid_manifest = yaml.safe_load(
            manifest("v0.2.1", upgrades_from=["v0.2.0"])
        )
        invalid_manifest["metadata"]["name"] = "v9.9.9"
        with self.assertRaisesRegex(CompatibilityError, "metadata.name"):
            validate_release_contract(
                "v0.2.0",
                "v0.2.1",
                yaml.safe_dump(invalid_manifest),
                migration("v0.2.1", old_tags=["v0.2.0"]),
                release("v0.2.1"),
                set(),
                FINGERPRINT,
            )
        with self.assertRaisesRegex(CompatibilityError, "mandatory headings"):
            validate_release_contract(
                "v0.2.0",
                "v0.2.1",
                manifest("v0.2.1", upgrades_from=["v0.2.0"]),
                migration("v0.2.1", old_tags=["v0.2.0"]).replace(
                    "## Recovery", "## Missing Recovery"
                ),
                release("v0.2.1"),
                set(),
                FINGERPRINT,
            )

    def test_unchanged_pin_still_requires_signer_variable_and_skips_network(self) -> None:
        def revision_reader(_root: Path, revision: str, _path: Path) -> str:
            self.assertIn(revision, {"a" * 40, "b" * 40})
            return source("v0.2.1")

        with self.assertRaisesRegex(
            CompatibilityError, "PLATFORM_RELEASE_SIGNER_FINGERPRINT"
        ):
            run_check(
                ROOT,
                "a" * 40,
                "b" * 40,
                "[]",
                "",
                None,
                revision_reader=revision_reader,
            )

        def unexpected_tag_fetch(_tag: str, _fingerprint: str) -> tuple[str, str]:
            self.fail("tag fetch must not run for an unchanged pin")

        def unexpected_release_fetch(_tag: str, _token: str | None) -> dict[str, Any]:
            self.fail("release fetch must not run for an unchanged pin")

        result = run_check(
            ROOT,
            "a" * 40,
            "b" * 40,
            "[]",
            FINGERPRINT,
            None,
            revision_reader=revision_reader,
            tag_fetcher=unexpected_tag_fetch,
            release_fetcher=unexpected_release_fetch,
        )
        self.assertFalse(result.changed)

    def test_classification_reads_explicit_revisions_without_network(self) -> None:
        revisions: list[str] = []

        def revision_reader(_root: Path, revision: str, _path: Path) -> str:
            revisions.append(revision)
            return source("v0.2.0" if revision == "a" * 40 else "v0.2.1")

        result = run_check(
            ROOT,
            "a" * 40,
            "b" * 40,
            "[]",
            FINGERPRINT,
            None,
            classify_only=True,
            revision_reader=revision_reader,
            tag_fetcher=lambda *_arguments: self.fail("classification fetched a tag"),
            release_fetcher=lambda *_arguments: self.fail("classification fetched a release"),
        )
        self.assertEqual(revisions, ["a" * 40, "b" * 40])
        self.assertTrue(result.changed)
        self.assertFalse(result.verified)

    def test_pull_request_fetch_rejects_a_head_sha_mismatch(self) -> None:
        with patch(
            "scripts.check_platform_compatibility.run_command",
            side_effect=["", "c" * 40],
        ):
            with self.assertRaisesRegex(CompatibilityError, "does not match event SHA"):
                fetch_pull_request_head(ROOT, 12, "b" * 40)

    def test_workflow_uses_trusted_base_environment_and_final_gate(self) -> None:
        workflow_path = ROOT / ".github/workflows/platform-compatibility.yaml"
        workflow = yaml.load(workflow_path.read_text(), Loader=yaml.BaseLoader)
        self.assertIn("pull_request_target", workflow["on"])
        self.assertNotIn("pull_request", workflow["on"])
        jobs = workflow["jobs"]
        self.assertEqual(jobs["platform_adoption"]["environment"], "platform-adoption")
        self.assertIn("always()", jobs["gate"]["if"])
        self.assertIn("platform_pin_changed", jobs["classify"]["outputs"])

        text = workflow_path.read_text(encoding="utf-8")
        self.assertIn("github.event.pull_request.base.sha", text)
        self.assertNotIn("ref: ${{ github.event.pull_request.head.sha }}", text)
        self.assertNotIn("make platform-compatibility", text)

    def test_all_workflow_actions_are_pinned_to_full_shas(self) -> None:
        for path in (ROOT / ".github/workflows").glob("*.yaml"):
            for line in path.read_text(encoding="utf-8").splitlines():
                if "uses:" not in line:
                    continue
                reference = line.split("uses:", 1)[1].strip().split()[0]
                with self.subTest(path=path.name, reference=reference):
                    self.assertRegex(reference, re.compile(r"@([0-9a-f]{40})$"))


if __name__ == "__main__":
    unittest.main()
