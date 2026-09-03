"""Offline tests for the trusted platform release compatibility gate."""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

import yaml

from scripts.check_platform_compatibility import (
    CLUSTER_KUSTOMIZATION_PATH,
    CLUSTER_RESOURCES,
    FLUX_COMPONENTS_PATH,
    FLUX_KUSTOMIZATION_PATH,
    FLUX_RESOURCES,
    FLUX_SYNC_PATH,
    PLATFORM_SOURCE_PATH,
    CompatibilityError,
    PlatformSource,
    VerifiedTag,
    fetch_pull_request_refs,
    parse_platform_source,
    parse_recovery_contract,
    parse_support_contract,
    parse_tag,
    run_check,
    run_command,
    source_ignore_paths,
    validate_release_contract,
)

ROOT = Path(__file__).resolve().parents[2]
FINGERPRINT = "SHA256:+rDcofrsfRE3ElJJxnUVoB3gmoEzZJUrisDqLZMHimw"


def source(
    tag: str,
    *,
    trust_secret: str = "k8s-stack-release-trust",
    adoption_mode: str = "upgrade",
    adoption_target: str | None = None,
    promoted_from_alpha: str | None = None,
) -> str:
    annotations = {
        "platform.neurwerk.com/adoption-mode": adoption_mode,
        "platform.neurwerk.com/adoption-target": adoption_target or tag,
    }
    if promoted_from_alpha is not None:
        annotations["platform.neurwerk.com/promoted-from-alpha"] = promoted_from_alpha
    return yaml.safe_dump(
        {
            "apiVersion": "source.toolkit.fluxcd.io/v1",
            "kind": "GitRepository",
            "metadata": {
                "annotations": annotations,
                "name": "k8s-stack",
                "namespace": "flux-system",
            },
            "spec": {
                "interval": "30s",
                "url": "https://github.com/neurwerk/k8s_stack_base.git",
                "ref": {"tag": tag},
                "verify": {
                    "mode": "Tag",
                    "secretRef": {"name": trust_secret},
                },
            },
        }
    )


def alpha_source(commit: str | None = None, **spec_overrides: Any) -> str:
    spec: dict[str, Any] = {
        "interval": "30s",
        "url": "https://github.com/neurwerk/k8s_stack_base.git",
        "ref": {"commit": commit} if commit is not None else {"branch": "main"},
        "verify": {
            "mode": "HEAD",
            "secretRef": {"name": "k8s-stack-alpha-trust"},
        },
    }
    spec.update(spec_overrides)
    return yaml.safe_dump(
        {
            "apiVersion": "source.toolkit.fluxcd.io/v1",
            "kind": "GitRepository",
            "metadata": {
                "annotations": {"platform.neurwerk.com/channel": "alpha"},
                "name": "k8s-stack",
                "namespace": "flux-system",
            },
            "spec": spec,
        }
    )


def control_plane_file(path: Path) -> str:
    """Return one canonical trusted composition-control fixture."""
    if path == CLUSTER_KUSTOMIZATION_PATH:
        return yaml.safe_dump(
            {
                "apiVersion": "kustomize.config.k8s.io/v1beta1",
                "kind": "Kustomization",
                "resources": CLUSTER_RESOURCES,
            },
            sort_keys=False,
        )
    if path == FLUX_KUSTOMIZATION_PATH:
        return yaml.safe_dump(
            {
                "apiVersion": "kustomize.config.k8s.io/v1beta1",
                "kind": "Kustomization",
                "resources": FLUX_RESOURCES,
            },
            sort_keys=False,
        )
    if path == FLUX_SYNC_PATH:
        documents = [
            {
                "apiVersion": "source.toolkit.fluxcd.io/v1",
                "kind": "GitRepository",
                "metadata": {"name": "flux-system", "namespace": "flux-system"},
                "spec": {
                    "interval": "1m0s",
                    "ref": {"branch": "main"},
                    "secretRef": {"name": "flux-system"},
                    "url": (
                        "ssh://git@github.com/neurwerk/k8s_stack_client_example_com.git"
                    ),
                },
            },
            {
                "apiVersion": "kustomize.toolkit.fluxcd.io/v1",
                "kind": "Kustomization",
                "metadata": {"name": "flux-system", "namespace": "flux-system"},
                "spec": {
                    "interval": "10m0s",
                    "path": "./clusters/prod-eu-1",
                    "prune": True,
                    "sourceRef": {"kind": "GitRepository", "name": "flux-system"},
                },
            },
        ]
        return "---\n" + "---\n".join(
            yaml.safe_dump(document, sort_keys=False) for document in documents
        )
    if path == FLUX_COMPONENTS_PATH:
        return "trusted generated Flux components\n"
    raise AssertionError(f"unexpected control-plane path: {path}")


def no_source_ignores(_root: Path, _revision: str) -> list[str]:
    """Model a canonical client artifact without source-controller exclusions."""
    return []


def manifest(
    tag: str,
    *,
    upgrades_from: list[str],
    fresh_install: str | None = None,
    downgrade: str = "unsupported",
    recovery: str = "replacement-restore",
    alpha_revisions: list[str] | None = None,
) -> str:
    compatibility: dict[str, Any] = {
        "upgradesFrom": upgrades_from,
        "downgrade": downgrade,
        "recovery": recovery,
    }
    if fresh_install is not None:
        compatibility["freshInstall"] = fresh_install
    if alpha_revisions is not None:
        compatibility["upgradesFromAlphaRevisions"] = alpha_revisions
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
                "compatibility": compatibility,
            },
        }
    )


def migration(
    tag: str,
    *,
    old_tags: list[str] | None = None,
    downgrade: str = "Unsupported",
    recovery: str = "Replacement restore",
    alpha_revisions: list[str] | None = None,
    fresh_install: str | None = None,
) -> str:
    old_tags = old_tags or []
    supported = (
        ", ".join(f"`{old_tag}`" for old_tag in old_tags) if old_tags else "None"
    )
    sections = {
        "Support": (
            (
                f"- Fresh installation: {fresh_install}.\n"
                if fresh_install is not None
                else ""
            )
            + f"- Supported source versions: {supported}.\n"
            + (
                "- Supported alpha source revisions: "
                + (
                    ", ".join(f"`{revision}`" for revision in alpha_revisions)
                    if alpha_revisions
                    else "None"
                )
                + ".\n"
                if alpha_revisions is not None
                else ""
            )
            + f"- Downgrade: {downgrade}."
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
        self.assertEqual(
            parse_platform_source(source("v1.2.3"), origin="test"),
            PlatformSource("stable", "tag", "v1.2.3", "upgrade"),
        )
        with self.assertRaisesRegex(CompatibilityError, "k8s-stack-release-trust"):
            parse_platform_source(
                source("v1.2.3", trust_secret="another-trust-root"), origin="test"
            )

    def test_platform_source_binds_adoption_intent_to_the_exact_tag(self) -> None:
        with self.assertRaisesRegex(CompatibilityError, "adoption-mode"):
            parse_platform_source(
                source("v1.2.3", adoption_mode="review-required"), origin="test"
            )
        with self.assertRaisesRegex(CompatibilityError, "adoption-target"):
            parse_platform_source(
                source("v1.2.3", adoption_target="v1.2.2"), origin="test"
            )

    def test_platform_source_rejects_fields_that_expand_the_signed_artifact(
        self,
    ) -> None:
        document = yaml.safe_load(source("v1.2.3"))
        document["spec"]["include"] = [{"repository": {"name": "flux-system"}}]
        with self.assertRaisesRegex(CompatibilityError, "canonical source spec"):
            parse_platform_source(yaml.safe_dump(document), origin="test")

    def test_alpha_source_has_one_closed_canonical_shape(self) -> None:
        self.assertEqual(
            parse_platform_source(alpha_source(), origin="test"),
            PlatformSource("alpha", "branch", "main"),
        )
        commit = "a" * 40
        self.assertEqual(
            parse_platform_source(alpha_source(commit), origin="test"),
            PlatformSource("alpha", "commit", commit),
        )
        invalid_specs = (
            {"ref": {"branch": "develop"}},
            {"ref": {"commit": "abc123"}},
            {"verify": {"mode": "Tag", "secretRef": {"name": "k8s-stack-alpha-trust"}}},
            {"verify": {"mode": "HEAD", "secretRef": {"name": "other-trust"}}},
            {"include": []},
        )
        for override in invalid_specs:
            with self.subTest(override=override), self.assertRaises(CompatibilityError):
                parse_platform_source(alpha_source(**override), origin="test")

    def test_stable_promotion_annotation_requires_a_full_commit_sha(self) -> None:
        revision = "a" * 40
        self.assertEqual(
            parse_platform_source(
                source("v1.2.3", promoted_from_alpha=revision), origin="test"
            ).promoted_from_alpha,
            revision,
        )
        with self.assertRaisesRegex(CompatibilityError, "full 40-hex"):
            parse_platform_source(
                source("v1.2.3", promoted_from_alpha="abc123"), origin="test"
            )

    def test_explicit_upgrade_path_is_accepted(self) -> None:
        validate_release_contract(
            "v0.2.0",
            "v0.2.1",
            manifest("v0.2.1", upgrades_from=["v0.2.0"]),
            migration("v0.2.1", old_tags=["v0.2.0"]),
            release("v0.2.1"),
            "upgrade",
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
                "upgrade",
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
            "upgrade",
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
                "upgrade",
                FINGERPRINT,
            )

    def test_malformed_source_version_continuations_are_rejected(self) -> None:
        cases = {
            "missing comma before wrap": (
                "- Supported source versions: `v0.2.0`\n  `v0.2.1`."
            ),
            "one-space indent": ("- Supported source versions: `v0.2.0`,\n `v0.2.1`."),
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
                f"{declaration}\n"
                "- Downgrade: Unsupported."
            )
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(CompatibilityError, "Supported source versions"),
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
                    "upgrade",
                    FINGERPRINT,
                )

        for target, old_tag in (
            ("v0.2.0", "v0.1.0"),
            ("v0.2.6", "v0.2.5"),
            ("v1.0.0", "v0.2.5"),
        ):
            with (
                self.subTest(target=target),
                self.assertRaisesRegex(
                    CompatibilityError, "legacy bare SemVer outside affected targets"
                ),
            ):
                validate_release_contract(
                    old_tag,
                    target,
                    manifest(target, upgrades_from=[old_tag.removeprefix("v")]),
                    migration(target, old_tags=[old_tag]),
                    release(target),
                    "upgrade",
                    FINGERPRINT,
                )

    def test_legacy_manifest_normalization_remains_strict_and_unique(self) -> None:
        for invalid in ("01.2.3", "0.2", "0.2.3-rc.1", ">=0.2.0"):
            with (
                self.subTest(value=invalid),
                self.assertRaisesRegex(CompatibilityError, "exact strict vX.Y.Z"),
            ):
                validate_release_contract(
                    "v0.2.0",
                    "v0.2.5",
                    manifest("v0.2.5", upgrades_from=[invalid]),
                    migration("v0.2.5", old_tags=["v0.2.0"]),
                    release("v0.2.5"),
                    "upgrade",
                    FINGERPRINT,
                )
        with self.assertRaisesRegex(CompatibilityError, "contains duplicates"):
            validate_release_contract(
                "v0.2.0",
                "v0.2.2",
                manifest("v0.2.2", upgrades_from=["0.2.0", "v0.2.0"]),
                migration("v0.2.2", old_tags=["v0.2.0"]),
                release("v0.2.2"),
                "upgrade",
                FINGERPRINT,
            )

    def test_known_downgrade_and_recovery_values_are_normalized(self) -> None:
        support = (
            "- Supported source versions: None.\n"
            "- Downgrade: Supported."
        )
        self.assertEqual(
            parse_support_contract(support), (set(), "supported")
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
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(CompatibilityError, error),
            ):
                validate_release_contract(
                    "v0.2.0",
                    "v0.2.1",
                    manifest("v0.2.1", upgrades_from=["v0.2.0"]),
                    migration_text,
                    release("v0.2.1"),
                    "upgrade",
                    FINGERPRINT,
                )
        with self.assertRaisesRegex(CompatibilityError, "manifest downgrade"):
            validate_release_contract(
                "v0.2.0",
                "v0.2.1",
                manifest("v0.2.1", upgrades_from=["v0.2.0"], downgrade="conditional"),
                valid,
                release("v0.2.1"),
                "upgrade",
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
                valid.replace(
                    declaration, "Recovery classification: Snapshot restore."
                ),
                "must be one of",
            ),
            "mismatch": (
                migration("v0.2.1", old_tags=["v0.2.0"], recovery="Forward fix"),
                "disagrees with the manifest",
            ),
        }
        for name, (migration_text, error) in cases.items():
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(CompatibilityError, error),
            ):
                validate_release_contract(
                    "v0.2.0",
                    "v0.2.1",
                    manifest("v0.2.1", upgrades_from=["v0.2.0"]),
                    migration_text,
                    release("v0.2.1"),
                    "upgrade",
                    FINGERPRINT,
                )
        with self.assertRaisesRegex(CompatibilityError, "manifest recovery"):
            validate_release_contract(
                "v0.2.0",
                "v0.2.1",
                manifest("v0.2.1", upgrades_from=["v0.2.0"], recovery="snapshot"),
                valid,
                release("v0.2.1"),
                "upgrade",
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
                "upgrade",
                FINGERPRINT,
            )

    def test_fresh_install_mode_is_commit_bound_and_explicit(self) -> None:
        arguments = (
            "v0.2.0",
            "v0.2.1",
            manifest("v0.2.1", upgrades_from=[]),
            migration("v0.2.1"),
            release("v0.2.1"),
        )
        with self.assertRaisesRegex(CompatibilityError, "does not support an upgrade"):
            validate_release_contract(*arguments, "upgrade", FINGERPRINT)
        validate_release_contract(*arguments, "fresh-install", FINGERPRINT)

    def test_v010_legacy_fresh_install_contract_remains_valid(self) -> None:
        validate_release_contract(
            "v0.1.0",
            "v0.1.0",
            manifest("v0.1.0", upgrades_from=[], fresh_install="supported"),
            migration("v0.1.0", fresh_install="Supported"),
            release("v0.1.0"),
            "fresh-install",
            FINGERPRINT,
            validate_transition=False,
        )

    def test_downgrade_and_unpublished_release_are_rejected(self) -> None:
        with self.assertRaisesRegex(CompatibilityError, "downgrade"):
            validate_release_contract(
                "v0.2.1",
                "v0.2.0",
                manifest("v0.2.0", upgrades_from=["v0.2.1"]),
                migration("v0.2.0", old_tags=["v0.2.1"]),
                release("v0.2.0"),
                "upgrade",
                FINGERPRINT,
            )
        with self.assertRaisesRegex(CompatibilityError, "published"):
            validate_release_contract(
                "v0.2.0",
                "v0.2.1",
                manifest("v0.2.1", upgrades_from=["v0.2.0"]),
                migration("v0.2.1", old_tags=["v0.2.0"]),
                release("v0.2.1", draft=True),
                "upgrade",
                FINGERPRINT,
            )

    def test_manifest_agreement_and_migration_headings_are_required(self) -> None:
        invalid_manifest = yaml.safe_load(manifest("v0.2.1", upgrades_from=["v0.2.0"]))
        invalid_manifest["metadata"]["name"] = "v9.9.9"
        with self.assertRaisesRegex(CompatibilityError, "metadata.name"):
            validate_release_contract(
                "v0.2.0",
                "v0.2.1",
                yaml.safe_dump(invalid_manifest),
                migration("v0.2.1", old_tags=["v0.2.0"]),
                release("v0.2.1"),
                "upgrade",
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
                "upgrade",
                FINGERPRINT,
            )

    def test_unchanged_pin_still_requires_signer_variable_and_skips_network(
        self,
    ) -> None:
        def revision_reader(_root: Path, revision: str, path: Path) -> str:
            self.assertIn(revision, {"a" * 40, "b" * 40})
            if path == PLATFORM_SOURCE_PATH:
                return source("v0.2.1")
            return control_plane_file(path)

        with self.assertRaisesRegex(
            CompatibilityError, "PLATFORM_RELEASE_SIGNER_FINGERPRINT"
        ):
            run_check(
                ROOT,
                "a" * 40,
                "b" * 40,
                "",
                None,
                revision_reader=revision_reader,
                source_ignore_finder=no_source_ignores,
            )

        def unexpected_tag_fetch(_tag: str, _fingerprint: str) -> tuple[str, str]:
            self.fail("tag fetch must not run for an unchanged pin")

        def unexpected_release_fetch(_tag: str, _token: str | None) -> dict[str, Any]:
            self.fail("release fetch must not run for an unchanged pin")

        result = run_check(
            ROOT,
            "a" * 40,
            "b" * 40,
            FINGERPRINT,
            None,
            revision_reader=revision_reader,
            source_ignore_finder=no_source_ignores,
            tag_fetcher=unexpected_tag_fetch,
            release_fetcher=unexpected_release_fetch,
        )
        self.assertFalse(result.changed)

    def test_classification_reads_explicit_revisions_without_network(self) -> None:
        revisions: list[str] = []

        def revision_reader(_root: Path, revision: str, path: Path) -> str:
            if path == PLATFORM_SOURCE_PATH:
                revisions.append(revision)
                return source("v0.2.0" if revision == "a" * 40 else "v0.2.1")
            return control_plane_file(path)

        result = run_check(
            ROOT,
            "a" * 40,
            "b" * 40,
            FINGERPRINT,
            None,
            classify_only=True,
            revision_reader=revision_reader,
            source_ignore_finder=no_source_ignores,
            tag_fetcher=lambda *_arguments: self.fail("classification fetched a tag"),
            release_fetcher=lambda *_arguments: self.fail(
                "classification fetched a release"
            ),
        )
        self.assertEqual(revisions, ["a" * 40, "b" * 40])
        self.assertTrue(result.changed)
        self.assertFalse(result.verified)

    def test_stable_to_alpha_requires_main_at_or_ahead_of_stable(self) -> None:
        base_sha = "a" * 40
        proposed_sha = "b" * 40

        def revision_reader(_root: Path, revision: str, path: Path) -> str:
            if path == PLATFORM_SOURCE_PATH:
                return source("v0.2.6") if revision == base_sha else alpha_source()
            return control_plane_file(path)

        resolved = {("tag", "v0.2.6"): "1" * 40, ("branch", "main"): "2" * 40}
        authenticated_tags: list[str] = []

        def authenticate_baseline(tag: str, _fingerprint: str) -> VerifiedTag:
            authenticated_tags.append(tag)
            return VerifiedTag("", "", resolved[("tag", tag)])

        result = run_check(
            ROOT,
            base_sha,
            proposed_sha,
            FINGERPRINT,
            None,
            revision_reader=revision_reader,
            source_ignore_finder=no_source_ignores,
            base_revision_fetcher=lambda selector, revision: resolved[(selector, revision)],
            ancestor_checker=lambda ancestor, descendant: (ancestor, descendant)
            == ("1" * 40, "2" * 40),
            tag_fetcher=authenticate_baseline,
        )
        self.assertEqual(result.new_source, PlatformSource("alpha", "branch", "main"))
        self.assertTrue(result.verified)
        self.assertEqual(authenticated_tags, ["v0.2.6"])

        with self.assertRaisesRegex(CompatibilityError, "behind or divergent"):
            run_check(
                ROOT,
                base_sha,
                proposed_sha,
                FINGERPRINT,
                None,
                revision_reader=revision_reader,
                source_ignore_finder=no_source_ignores,
                base_revision_fetcher=lambda selector, revision: resolved[(selector, revision)],
                ancestor_checker=lambda _ancestor, _descendant: False,
                tag_fetcher=authenticate_baseline,
            )

    def test_alpha_branch_resolves_even_when_source_is_unchanged(self) -> None:
        resolved = "1" * 40

        def revision_reader(_root: Path, _revision: str, path: Path) -> str:
            return alpha_source() if path == PLATFORM_SOURCE_PATH else control_plane_file(path)

        result = run_check(
            ROOT,
            "a" * 40,
            "b" * 40,
            "",
            None,
            revision_reader=revision_reader,
            source_ignore_finder=no_source_ignores,
            base_revision_fetcher=lambda selector, revision: resolved,
            ancestor_checker=lambda *_arguments: self.fail("alpha ancestry was checked"),
        )
        self.assertFalse(result.changed)
        self.assertFalse(result.verified)
        self.assertEqual(result.old_alpha_commit, resolved)
        self.assertEqual(result.new_alpha_commit, resolved)

    def test_alpha_resolution_must_match_classification_expectations(self) -> None:
        classified = "1" * 40
        moved = "2" * 40

        def revision_reader(_root: Path, revision: str, path: Path) -> str:
            if path == PLATFORM_SOURCE_PATH:
                return alpha_source() if revision == "a" * 40 else alpha_source(classified)
            return control_plane_file(path)

        with self.assertRaisesRegex(CompatibilityError, "resolved old alpha commit changed"):
            run_check(
                ROOT,
                "a" * 40,
                "b" * 40,
                "",
                None,
                expected_old_alpha_commit=classified,
                expected_new_alpha_commit=classified,
                revision_reader=revision_reader,
                source_ignore_finder=no_source_ignores,
                base_revision_fetcher=lambda selector, revision: (
                    moved if selector == "branch" else revision
                ),
                ancestor_checker=lambda ancestor, descendant: ancestor == classified
                and descendant == moved,
            )

        def unfreeze_reader(_root: Path, revision: str, path: Path) -> str:
            if path == PLATFORM_SOURCE_PATH:
                return alpha_source(classified) if revision == "a" * 40 else alpha_source()
            return control_plane_file(path)

        with self.assertRaisesRegex(CompatibilityError, "resolved new alpha commit changed"):
            run_check(
                ROOT,
                "a" * 40,
                "b" * 40,
                "",
                None,
                expected_old_alpha_commit=classified,
                expected_new_alpha_commit=classified,
                revision_reader=unfreeze_reader,
                source_ignore_finder=no_source_ignores,
                base_revision_fetcher=lambda selector, revision: (
                    moved if selector == "branch" else revision
                ),
                ancestor_checker=lambda ancestor, descendant: (ancestor, descendant)
                == (classified, moved),
            )

    def test_alpha_freeze_and_unfreeze_require_protected_main_ancestry(self) -> None:
        pinned = "1" * 40
        main = "2" * 40

        def transition_reader(old: str, new: str):
            def revision_reader(_root: Path, revision: str, path: Path) -> str:
                if path == PLATFORM_SOURCE_PATH:
                    return old if revision == "a" * 40 else new
                return control_plane_file(path)

            return revision_reader

        for old, new in (
            (alpha_source(), alpha_source(main)),
            (alpha_source(pinned), alpha_source()),
        ):
            with self.subTest(old=old, new=new):
                result = run_check(
                    ROOT,
                    "a" * 40,
                    "b" * 40,
                    "",
                    None,
                    revision_reader=transition_reader(old, new),
                    source_ignore_finder=no_source_ignores,
                    base_revision_fetcher=lambda selector, revision: (
                        main if selector == "branch" else revision
                    ),
                    ancestor_checker=lambda ancestor, descendant: (ancestor, descendant)
                    == (pinned, main),
                )
                self.assertTrue(result.changed)
                self.assertTrue(result.verified)

        with self.assertRaisesRegex(CompatibilityError, "must exactly equal"):
            run_check(
                ROOT,
                "a" * 40,
                "b" * 40,
                "",
                None,
                revision_reader=transition_reader(alpha_source(), alpha_source(pinned)),
                source_ignore_finder=no_source_ignores,
                base_revision_fetcher=lambda selector, revision: (
                    main if selector == "branch" else revision
                ),
                ancestor_checker=lambda ancestor, descendant: (ancestor, descendant)
                == (pinned, main),
            )

    def test_moving_alpha_branch_cannot_transition_directly_to_stable(self) -> None:
        observed = "1" * 40

        def revision_reader(_root: Path, revision: str, path: Path) -> str:
            if path == PLATFORM_SOURCE_PATH:
                return (
                    alpha_source()
                    if revision == "a" * 40
                    else source("v0.3.0", promoted_from_alpha=observed)
                )
            return control_plane_file(path)

        with self.assertRaisesRegex(CompatibilityError, "freeze the source"):
            run_check(
                ROOT,
                "a" * 40,
                "b" * 40,
                FINGERPRINT,
                None,
                classify_only=True,
                revision_reader=revision_reader,
                source_ignore_finder=no_source_ignores,
                base_revision_fetcher=lambda selector, revision: observed,
            )

    def test_alpha_to_stable_exact_commit_is_a_zero_change_promotion(self) -> None:
        observed = "1" * 40
        target = "v0.3.0"

        def revision_reader(_root: Path, revision: str, path: Path) -> str:
            if path == PLATFORM_SOURCE_PATH:
                if revision == "a" * 40:
                    return alpha_source(observed)
                return source(target, promoted_from_alpha=observed)
            return control_plane_file(path)

        result = run_check(
            ROOT,
            "a" * 40,
            "b" * 40,
            FINGERPRINT,
            None,
            revision_reader=revision_reader,
            source_ignore_finder=no_source_ignores,
            base_revision_fetcher=lambda selector, revision: observed,
            ancestor_checker=lambda *_arguments: self.fail("exact commits need no ancestry"),
            tag_fetcher=lambda _tag, _fingerprint: VerifiedTag(
                manifest(target, upgrades_from=[]), migration(target), observed
            ),
            release_fetcher=lambda _tag, _token: release(target),
        )
        self.assertTrue(result.changed)
        self.assertTrue(result.verified)

    def test_exact_alpha_promotion_validates_complete_release_contract(self) -> None:
        observed = "1" * 40
        target = "v0.3.0"

        def revision_reader(_root: Path, revision: str, path: Path) -> str:
            if path == PLATFORM_SOURCE_PATH:
                return (
                    alpha_source(observed)
                    if revision == "a" * 40
                    else source(target, promoted_from_alpha=observed)
                )
            return control_plane_file(path)

        with self.assertRaisesRegex(CompatibilityError, "downgrade support disagrees"):
            run_check(
                ROOT,
                "a" * 40,
                "b" * 40,
                FINGERPRINT,
                None,
                revision_reader=revision_reader,
                source_ignore_finder=no_source_ignores,
                base_revision_fetcher=lambda selector, revision: observed,
                tag_fetcher=lambda _tag, _fingerprint: VerifiedTag(
                    manifest(target, upgrades_from=[]),
                    migration(target, downgrade="Supported"),
                    observed,
                ),
                release_fetcher=lambda _tag, _token: release(target),
            )

    def test_fresh_alpha_promotion_uses_invariant_support(self) -> None:
        observed = "1" * 40
        target = "v0.3.0"

        def revision_reader(_root: Path, revision: str, path: Path) -> str:
            if path == PLATFORM_SOURCE_PATH:
                return (
                    alpha_source(observed)
                    if revision == "a" * 40
                    else source(
                        target,
                        adoption_mode="fresh-install",
                        promoted_from_alpha=observed,
                    )
                )
            return control_plane_file(path)

        result = run_check(
            ROOT,
            "a" * 40,
            "b" * 40,
            FINGERPRINT,
            None,
            revision_reader=revision_reader,
            source_ignore_finder=no_source_ignores,
            base_revision_fetcher=lambda selector, revision: observed,
            tag_fetcher=lambda _tag, _fingerprint: VerifiedTag(
                manifest(target, upgrades_from=[]), migration(target), observed
            ),
            release_fetcher=lambda _tag, _token: release(target),
        )
        self.assertTrue(result.verified)

    def test_forward_alpha_promotion_requires_revision_in_both_contracts(self) -> None:
        observed = "1" * 40
        target_commit = "2" * 40
        target = "v0.3.0"

        def revision_reader(_root: Path, revision: str, path: Path) -> str:
            if path == PLATFORM_SOURCE_PATH:
                if revision == "a" * 40:
                    return alpha_source(observed)
                return source(target, promoted_from_alpha=observed)
            return control_plane_file(path)

        common: dict[str, Any] = {
            "revision_reader": revision_reader,
            "source_ignore_finder": no_source_ignores,
            "base_revision_fetcher": lambda selector, revision: observed,
            "ancestor_checker": lambda ancestor, descendant: (ancestor, descendant)
            == (observed, target_commit),
            "release_fetcher": lambda _tag, _token: release(target),
        }
        with self.assertRaisesRegex(CompatibilityError, "does not list"):
            run_check(
                ROOT,
                "a" * 40,
                "b" * 40,
                FINGERPRINT,
                None,
                tag_fetcher=lambda _tag, _fingerprint: VerifiedTag(
                    manifest(target, upgrades_from=[], alpha_revisions=[]),
                    migration(target, alpha_revisions=[]),
                    target_commit,
                ),
                **common,
            )

        extra_revision = "3" * 40
        with self.assertRaisesRegex(CompatibilityError, "must exactly equal"):
            run_check(
                ROOT,
                "a" * 40,
                "b" * 40,
                FINGERPRINT,
                None,
                tag_fetcher=lambda _tag, _fingerprint: VerifiedTag(
                    manifest(
                        target,
                        upgrades_from=[],
                        alpha_revisions=[observed, extra_revision],
                    ),
                    migration(target, alpha_revisions=[observed]),
                    target_commit,
                ),
                **common,
            )

        result = run_check(
            ROOT,
            "a" * 40,
            "b" * 40,
            FINGERPRINT,
            None,
            tag_fetcher=lambda _tag, _fingerprint: VerifiedTag(
                manifest(target, upgrades_from=[], alpha_revisions=[observed]),
                migration(target, alpha_revisions=[observed]),
                target_commit,
            ),
            **common,
        )
        self.assertTrue(result.verified)

    def test_alpha_promotion_rejects_stale_observation_and_non_descendant(self) -> None:
        observed = "1" * 40
        target_commit = "2" * 40

        def reader_with_promotion(promoted: str):
            def revision_reader(_root: Path, revision: str, path: Path) -> str:
                if path == PLATFORM_SOURCE_PATH:
                    return (
                        alpha_source(observed)
                        if revision == "a" * 40
                        else source("v0.3.0", promoted_from_alpha=promoted)
                    )
                return control_plane_file(path)

            return revision_reader

        with self.assertRaisesRegex(CompatibilityError, "must equal the exact observed"):
            run_check(
                ROOT,
                "a" * 40,
                "b" * 40,
                FINGERPRINT,
                None,
                classify_only=True,
                revision_reader=reader_with_promotion("3" * 40),
                source_ignore_finder=no_source_ignores,
                base_revision_fetcher=lambda selector, revision: observed,
            )
        with self.assertRaisesRegex(CompatibilityError, "behind or divergent"):
            run_check(
                ROOT,
                "a" * 40,
                "b" * 40,
                FINGERPRINT,
                None,
                classify_only=True,
                revision_reader=reader_with_promotion(observed),
                source_ignore_finder=no_source_ignores,
                base_revision_fetcher=lambda selector, revision: (
                    target_commit if selector == "tag" else observed
                ),
                ancestor_checker=lambda _ancestor, _descendant: False,
            )

    def test_adoption_mode_cannot_change_without_a_new_tag(self) -> None:
        def revision_reader(_root: Path, revision: str, path: Path) -> str:
            if path == PLATFORM_SOURCE_PATH:
                mode = "upgrade" if revision == "a" * 40 else "fresh-install"
                return source("v0.2.1", adoption_mode=mode)
            return control_plane_file(path)

        with self.assertRaisesRegex(
            CompatibilityError, "annotations may change only"
        ):
            run_check(
                ROOT,
                "a" * 40,
                "b" * 40,
                FINGERPRINT,
                None,
                revision_reader=revision_reader,
                source_ignore_finder=no_source_ignores,
            )

    def test_composition_controls_cannot_transform_the_platform_source(self) -> None:
        base_sha = "a" * 40
        proposed_sha = "b" * 40

        def transformed_reader(_root: Path, revision: str, path: Path) -> str:
            if path == PLATFORM_SOURCE_PATH:
                return source("v0.2.1")
            content = control_plane_file(path)
            if revision == proposed_sha and path == CLUSTER_KUSTOMIZATION_PATH:
                document = yaml.safe_load(content)
                document["patches"] = [
                    {
                        "target": {"kind": "GitRepository", "name": "k8s-stack"},
                        "patch": "- op: remove\n  path: /spec/verify\n",
                    }
                ]
                return yaml.safe_dump(document)
            return content

        with self.assertRaisesRegex(CompatibilityError, "transform-free"):
            run_check(
                ROOT,
                base_sha,
                proposed_sha,
                FINGERPRINT,
                None,
                revision_reader=transformed_reader,
                source_ignore_finder=no_source_ignores,
            )

    def test_flux_bootstrap_controls_cannot_change_around_the_raw_source(self) -> None:
        base_sha = "a" * 40
        proposed_sha = "b" * 40

        def patched_sync_reader(_root: Path, revision: str, path: Path) -> str:
            if path == PLATFORM_SOURCE_PATH:
                return source("v0.2.1")
            content = control_plane_file(path)
            if revision == proposed_sha and path == FLUX_SYNC_PATH:
                documents = list(yaml.safe_load_all(content))
                documents[1]["spec"]["patches"] = [
                    {
                        "target": {"kind": "GitRepository", "name": "k8s-stack"},
                        "patch": "- op: remove\n  path: /spec/verify\n",
                    }
                ]
                return "---\n" + "---\n".join(
                    yaml.safe_dump(document, sort_keys=False) for document in documents
                )
            return content

        with self.assertRaisesRegex(CompatibilityError, "canonical bootstrap spec"):
            run_check(
                ROOT,
                base_sha,
                proposed_sha,
                FINGERPRINT,
                None,
                revision_reader=patched_sync_reader,
                source_ignore_finder=no_source_ignores,
            )

        def replaced_components_reader(_root: Path, revision: str, path: Path) -> str:
            if path == PLATFORM_SOURCE_PATH:
                return source("v0.2.1")
            if revision == proposed_sha and path == FLUX_COMPONENTS_PATH:
                return "attacker-controlled Flux components\n"
            return control_plane_file(path)

        with self.assertRaisesRegex(CompatibilityError, "bootstrap controls"):
            run_check(
                ROOT,
                base_sha,
                proposed_sha,
                FINGERPRINT,
                None,
                revision_reader=replaced_components_reader,
                source_ignore_finder=no_source_ignores,
            )

    def test_source_controller_ignore_files_cannot_hide_checked_composition(
        self,
    ) -> None:
        base_sha = "a" * 40
        proposed_sha = "b" * 40

        def revision_reader(_root: Path, _revision: str, path: Path) -> str:
            if path == PLATFORM_SOURCE_PATH:
                return source("v0.2.1")
            return control_plane_file(path)

        def source_ignore_finder(_root: Path, revision: str) -> list[str]:
            if revision == proposed_sha:
                return ["clusters/prod-eu-1/.sourceignore"]
            return []

        with self.assertRaisesRegex(CompatibilityError, "prohibited.*sourceignore"):
            run_check(
                ROOT,
                base_sha,
                proposed_sha,
                FINGERPRINT,
                None,
                revision_reader=revision_reader,
                source_ignore_finder=source_ignore_finder,
            )

        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            run_command(["git", "init", "--quiet"], cwd=repository)
            ignored_directory = repository / "nested-é"
            ignored_directory.mkdir()
            (ignored_directory / ".sourceignore").write_text("*.yaml\n")
            run_command(["git", "add", "."], cwd=repository)
            run_command(
                [
                    "git",
                    "-c",
                    "user.name=Platform Test",
                    "-c",
                    "user.email=platform-test@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "fixture",
                ],
                cwd=repository,
            )
            revision = run_command(["git", "rev-parse", "HEAD"], cwd=repository).strip()
            self.assertEqual(
                source_ignore_paths(repository, revision),
                ["nested-é/.sourceignore"],
            )

    def test_pull_request_fetch_rejects_a_head_sha_mismatch(self) -> None:
        with (
            patch(
                "scripts.check_platform_compatibility.run_command",
                side_effect=["", "c" * 40, "d" * 40],
            ),
            self.assertRaisesRegex(CompatibilityError, "does not match event SHA"),
        ):
            fetch_pull_request_refs(ROOT, 12, "a" * 40, "b" * 40, "d" * 40)

    def test_pull_request_fetch_requires_the_exact_test_merge_parents(self) -> None:
        base_sha = "a" * 40
        head_sha = "b" * 40
        merge_sha = "c" * 40
        with patch(
            "scripts.check_platform_compatibility.run_command",
            side_effect=[
                "",
                head_sha,
                merge_sha,
                f"{merge_sha} {base_sha} {head_sha}",
            ],
        ):
            fetch_pull_request_refs(ROOT, 12, base_sha, head_sha, merge_sha)

        with (
            patch(
                "scripts.check_platform_compatibility.run_command",
                side_effect=[
                    "",
                    head_sha,
                    merge_sha,
                    f"{merge_sha} {'d' * 40} {head_sha}",
                ],
            ),
            self.assertRaisesRegex(CompatibilityError, "exact current base"),
        ):
            fetch_pull_request_refs(ROOT, 12, base_sha, head_sha, merge_sha)

    def test_pull_request_fetch_preserves_parents_in_a_shallow_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            origin = temporary_root / "origin.git"
            source_repository = temporary_root / "source"
            checker = temporary_root / "checker"
            origin.mkdir()
            source_repository.mkdir()
            checker.mkdir()
            run_command(["git", "init", "--bare", "--quiet"], cwd=origin)
            run_command(["git", "init", "--quiet"], cwd=source_repository)
            run_command(
                ["git", "config", "user.name", "Compatibility Test"],
                cwd=source_repository,
            )
            run_command(
                ["git", "config", "user.email", "compatibility@example.invalid"],
                cwd=source_repository,
            )
            (source_repository / "state").write_text("base\n", encoding="utf-8")
            run_command(["git", "add", "state"], cwd=source_repository)
            run_command(
                ["git", "commit", "--quiet", "-m", "base"], cwd=source_repository
            )
            base_sha = run_command(
                ["git", "rev-parse", "HEAD"], cwd=source_repository
            ).strip()
            run_command(
                ["git", "switch", "--quiet", "-c", "pull-request"],
                cwd=source_repository,
            )
            (source_repository / "state").write_text("head\n", encoding="utf-8")
            run_command(
                ["git", "commit", "--quiet", "-am", "head"], cwd=source_repository
            )
            head_sha = run_command(
                ["git", "rev-parse", "HEAD"], cwd=source_repository
            ).strip()
            run_command(
                ["git", "switch", "--quiet", "--detach", base_sha],
                cwd=source_repository,
            )
            run_command(
                [
                    "git",
                    "merge",
                    "--quiet",
                    "--no-ff",
                    "pull-request",
                    "-m",
                    "test merge",
                ],
                cwd=source_repository,
            )
            merge_sha = run_command(
                ["git", "rev-parse", "HEAD"], cwd=source_repository
            ).strip()
            run_command(
                ["git", "remote", "add", "origin", origin.as_uri()],
                cwd=source_repository,
            )
            run_command(
                [
                    "git",
                    "push",
                    "--quiet",
                    "origin",
                    f"{head_sha}:refs/pull/12/head",
                    f"{merge_sha}:refs/pull/12/merge",
                ],
                cwd=source_repository,
            )
            run_command(["git", "init", "--quiet"], cwd=checker)
            run_command(
                ["git", "remote", "add", "origin", origin.as_uri()], cwd=checker
            )

            fetch_pull_request_refs(checker, 12, base_sha, head_sha, merge_sha)

    def test_workflow_uses_trusted_controller_and_status_app(self) -> None:
        workflow_path = ROOT / ".github/workflows/platform-compatibility.yaml"
        workflow = yaml.load(workflow_path.read_text(), Loader=yaml.BaseLoader)
        self.assertIn("pull_request_target", workflow["on"])
        self.assertNotIn("pull_request", workflow["on"])
        self.assertIn("edited", workflow["on"]["pull_request_target"]["types"])
        self.assertNotIn("labeled", workflow["on"]["pull_request_target"]["types"])
        self.assertEqual(
            workflow["jobs"]["evaluate"]["uses"],
            "./.github/workflows/platform-compatibility-evaluate.yaml",
        )
        self.assertNotIn("secrets", workflow["jobs"]["evaluate"])

        evaluate_path = ROOT / ".github/workflows/platform-compatibility-evaluate.yaml"
        evaluate = yaml.load(evaluate_path.read_text(), Loader=yaml.BaseLoader)
        jobs = evaluate["jobs"]
        self.assertEqual(
            jobs["platform_adoption"]["environment"]["name"],
            "platform-adoption",
        )
        self.assertEqual(jobs["classify"]["environment"]["name"], "platform-status")
        self.assertEqual(jobs["finalize"]["environment"]["name"], "platform-status")
        self.assertIn("always()", jobs["finalize"]["if"])
        self.assertIn("platform_source_changed", jobs["classify"]["outputs"])
        self.assertIn("new_source_channel", jobs["classify"]["outputs"])
        self.assertIn("new_source_selector", jobs["classify"]["outputs"])
        self.assertIn("new_source_revision", jobs["classify"]["outputs"])
        self.assertIn("old_alpha_commit", jobs["classify"]["outputs"])
        self.assertIn("new_alpha_commit", jobs["classify"]["outputs"])
        self.assertTrue(
            all(job.get("name") != "Platform Compatibility" for job in jobs.values())
        )

        validate = yaml.load(
            (ROOT / ".github/workflows/validate.yaml").read_text(),
            Loader=yaml.BaseLoader,
        )
        self.assertEqual(validate["jobs"]["validate"]["name"], "Required CI")

        text = evaluate_path.read_text(encoding="utf-8")
        self.assertIn("actions/create-github-app-token@", text)
        self.assertIn("permission-statuses: write", text)
        self.assertIn("--merge-sha", text)
        self.assertIn("--expected-old-alpha-commit", text)
        self.assertIn("--expected-new-alpha-commit", text)
        self.assertIn("Resolved old alpha commit", text)
        self.assertIn("Resolved new alpha commit", text)
        self.assertIn("secrets.PLATFORM_STATUS_APP_PRIVATE_KEY", text)
        self.assertNotIn("--labels-json", text)
        self.assertNotIn("ref: ${{ github.event.pull_request.head.sha }}", text)
        self.assertNotIn("make platform-compatibility", text)

        refresh = yaml.load(
            (
                ROOT / ".github/workflows/platform-compatibility-refresh.yaml"
            ).read_text(),
            Loader=yaml.BaseLoader,
        )
        self.assertIn("push", refresh["on"])
        self.assertNotIn("workflow_dispatch", refresh["on"])
        self.assertNotIn("secrets", refresh["jobs"]["evaluate"])

    def test_all_workflow_actions_are_pinned_to_full_shas(self) -> None:
        for path in (ROOT / ".github/workflows").glob("*.yaml"):
            for line in path.read_text(encoding="utf-8").splitlines():
                match = re.match(r"^\s*uses:\s*([^\s#]+)", line)
                if match is None:
                    continue
                reference = match.group(1)
                if reference.startswith("./"):
                    continue
                with self.subTest(path=path.name, reference=reference):
                    self.assertRegex(reference, re.compile(r"@([0-9a-f]{40})$"))


if __name__ == "__main__":
    unittest.main()
