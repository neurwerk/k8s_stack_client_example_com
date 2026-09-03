#!/usr/bin/env python3
"""Verify that a pull request selects an authentic, compatible platform release."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

import yaml

PLATFORM_SOURCE_PATH = Path("clusters/prod-eu-1/platform-source.yaml")
CLUSTER_KUSTOMIZATION_PATH = Path("clusters/prod-eu-1/kustomization.yaml")
FLUX_KUSTOMIZATION_PATH = Path("clusters/prod-eu-1/flux-system/kustomization.yaml")
FLUX_SYNC_PATH = Path("clusters/prod-eu-1/flux-system/gotk-sync.yaml")
FLUX_COMPONENTS_PATH = Path("clusters/prod-eu-1/flux-system/gotk-components.yaml")
PLATFORM_SOURCE_URL = "https://github.com/neurwerk/k8s_stack_base.git"
PLATFORM_RELEASE_API = (
    "https://api.github.com/repos/neurwerk/k8s_stack_base/releases/tags/"
)
TRUST_KEY_PATH = "release/trust/platform-release.sshpub"
ADOPTION_MODE_ANNOTATION = "platform.neurwerk.com/adoption-mode"
ADOPTION_TARGET_ANNOTATION = "platform.neurwerk.com/adoption-target"
CHANNEL_ANNOTATION = "platform.neurwerk.com/channel"
PROMOTED_FROM_ALPHA_ANNOTATION = "platform.neurwerk.com/promoted-from-alpha"
ADOPTION_MODES = {"fresh-install", "upgrade"}
CLUSTER_RESOURCES = [
    "cluster-identity.yaml",
    "platform-source.yaml",
    "namespaces.yaml",
    "client-values.yaml",
    "infrastructure.yaml",
    "applications.yaml",
    "flux-system",
]
FLUX_RESOURCES = ["gotk-components.yaml", "gotk-sync.yaml"]
TAG_PATTERN = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
FINGERPRINT_PATTERN = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
SHA_PATTERN = re.compile(r"^[0-9a-f]{40,64}$")
COMMIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
CLIENT_SOURCE_URL_PATTERN = re.compile(
    r"^ssh://git@github\.com/neurwerk/k8s_stack_client_[a-z0-9_]+\.git$"
)
MAX_REVISION_FILE_BYTES = 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 60
LEGACY_UPGRADES_FROM_TARGETS = {"v0.1.0", "v0.1.1"}
MANDATORY_MIGRATION_HEADINGS = {
    "Support",
    "Prerequisites",
    "Client Actions",
    "Stateful And API Effects",
    "Pre-Deployment Checks",
    "Post-Deployment Checks",
    "Recovery",
    "Exclusions",
}
COMPATIBILITY_DISPLAY_VALUES = {
    "Supported": "supported",
    "Unsupported": "unsupported",
}
RECOVERY_DISPLAY_VALUES = {
    "Configuration revert": "configuration-revert",
    "Forward fix": "forward-fix",
    "Component native restore": "component-native-restore",
    "Replacement restore": "replacement-restore",
}
STABLE_UPGRADE_DISPLAY_VALUES = {
    "Supported": "supported",
    "Fresh installation only": "fresh-install-only",
}


class CompatibilityError(RuntimeError):
    """A platform transition failed a required review gate."""


@dataclass(frozen=True)
class CheckResult:
    """Machine-readable platform source classification and verification result."""

    old_source: PlatformSource
    new_source: PlatformSource
    old_alpha_commit: str | None
    new_alpha_commit: str | None
    changed: bool
    verified: bool


@dataclass(frozen=True)
class PlatformSource:
    """One canonical stable release or alpha development source."""

    channel: str
    selector: str
    revision: str
    adoption_mode: str | None = None
    promoted_from_alpha: str | None = None


@dataclass(frozen=True)
class VerifiedTag:
    """Authenticated release content and the commit peeled from its signed tag."""

    manifest: str
    migration: str
    commit: str


def run_command(arguments: list[str], *, cwd: Path | None = None) -> str:
    """Run a local command and return stdout with a bounded failure message."""
    try:
        result = subprocess.run(
            arguments,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise CompatibilityError(
            f"command timed out after {COMMAND_TIMEOUT_SECONDS} seconds: {arguments[0]}"
        ) from error
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise CompatibilityError(
            f"command failed ({' '.join(arguments)}): {detail[:1000]}"
        )
    return result.stdout


def parse_tag(tag: Any, *, field: str) -> tuple[int, int, int]:
    """Parse one strict vX.Y.Z tag without ranges or prerelease syntax."""
    if not isinstance(tag, str):
        raise CompatibilityError(f"{field} must be a string")
    match = TAG_PATTERN.fullmatch(tag)
    if match is None:
        raise CompatibilityError(f"{field} must be an exact strict vX.Y.Z tag: {tag!r}")
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch)


def parse_platform_source(content: str, *, origin: str) -> PlatformSource:
    """Parse one closed canonical stable or alpha platform source."""
    try:
        source = yaml.safe_load(content)
        if not isinstance(source, dict):
            raise CompatibilityError(f"{origin} must contain one source mapping")
        metadata = source["metadata"]
        spec = source["spec"]
        if not isinstance(metadata, dict) or not isinstance(spec, dict):
            raise CompatibilityError(f"{origin} must use source mappings")
        annotations = metadata["annotations"]
        reference = spec["ref"]
        verification = spec["verify"]
        secret_reference = verification["secretRef"]
        if not all(
            isinstance(value, dict)
            for value in (
                annotations,
                reference,
                verification,
                secret_reference,
            )
        ):
            raise CompatibilityError(f"{origin} must use canonical source mappings")
    except (TypeError, KeyError, yaml.YAMLError) as error:
        raise CompatibilityError(
            f"cannot parse platform source from {origin}"
        ) from error

    if set(source) != {"apiVersion", "kind", "metadata", "spec"}:
        raise CompatibilityError(f"{origin} must use the canonical source shape")
    if source["apiVersion"] != "source.toolkit.fluxcd.io/v1":
        raise CompatibilityError(f"{origin} must use the canonical source API")
    if source["kind"] != "GitRepository":
        raise CompatibilityError(f"{origin} must be a GitRepository")
    if metadata != {
        "annotations": annotations,
        "name": "k8s-stack",
        "namespace": "flux-system",
    }:
        raise CompatibilityError(f"{origin} must use canonical source metadata")
    if set(spec) != {"interval", "url", "ref", "verify"}:
        raise CompatibilityError(f"{origin} must use the canonical source spec")
    if spec["interval"] != "30s":
        raise CompatibilityError(f"{origin} must retain the canonical interval")
    if spec.get("url") != PLATFORM_SOURCE_URL:
        raise CompatibilityError(
            f"{origin} must use public source {PLATFORM_SOURCE_URL}"
        )
    if set(verification) != {"mode", "secretRef"} or set(secret_reference) != {
        "name"
    }:
        raise CompatibilityError(f"{origin} must use canonical source verification")

    if annotations == {CHANNEL_ANNOTATION: "alpha"}:
        if reference == {"branch": "main"}:
            selector = "branch"
            revision = "main"
        elif set(reference) == {"commit"} and isinstance(reference["commit"], str):
            selector = "commit"
            revision = reference["commit"]
            if COMMIT_SHA_PATTERN.fullmatch(revision) is None:
                raise CompatibilityError(
                    f"{origin} alpha commit must be a full 40-hex SHA"
                )
        else:
            raise CompatibilityError(
                f"{origin} alpha source must select branch main or one full commit"
            )
        if verification.get("mode") != "HEAD":
            raise CompatibilityError(
                f"{origin} alpha source must use Flux HEAD verification"
            )
        if secret_reference.get("name") != "k8s-stack-alpha-trust":
            raise CompatibilityError(
                f"{origin} alpha source must use trust Secret k8s-stack-alpha-trust"
            )
        return PlatformSource(channel="alpha", selector=selector, revision=revision)

    allowed_stable_annotations = {
        ADOPTION_MODE_ANNOTATION,
        ADOPTION_TARGET_ANNOTATION,
    }
    if set(annotations) not in (
        allowed_stable_annotations,
        allowed_stable_annotations | {PROMOTED_FROM_ALPHA_ANNOTATION},
    ):
        raise CompatibilityError(f"{origin} must use canonical source annotations")
    if set(reference) != {"tag"}:
        raise CompatibilityError(f"{origin} stable source must select exactly one tag")
    if verification.get("mode") != "Tag":
        raise CompatibilityError(f"{origin} stable source must retain Flux tag verification")
    if secret_reference.get("name") != "k8s-stack-release-trust":
        raise CompatibilityError(
            f"{origin} must use trust Secret k8s-stack-release-trust"
        )

    tag = reference["tag"]
    parse_tag(tag, field=f"{origin} platform pin")
    adoption_mode = annotations.get(ADOPTION_MODE_ANNOTATION)
    if adoption_mode not in ADOPTION_MODES:
        known = ", ".join(sorted(ADOPTION_MODES))
        raise CompatibilityError(
            f"{origin} annotation {ADOPTION_MODE_ANNOTATION} must be one of: {known}"
        )
    adoption_target = annotations.get(ADOPTION_TARGET_ANNOTATION)
    if adoption_target != tag:
        raise CompatibilityError(
            f"{origin} annotation {ADOPTION_TARGET_ANNOTATION} must equal {tag}"
        )
    promoted_from_alpha = annotations.get(PROMOTED_FROM_ALPHA_ANNOTATION)
    if promoted_from_alpha is not None and COMMIT_SHA_PATTERN.fullmatch(
        promoted_from_alpha
    ) is None:
        raise CompatibilityError(
            f"{origin} annotation {PROMOTED_FROM_ALPHA_ANNOTATION} must be a full "
            "40-hex commit SHA"
        )
    return PlatformSource(
        channel="stable",
        selector="tag",
        revision=tag,
        adoption_mode=adoption_mode,
        promoted_from_alpha=promoted_from_alpha,
    )


def parse_kustomization(content: str, *, origin: str, resources: list[str]) -> None:
    """Require one transform-free Kustomization with the exact resource inventory."""
    try:
        document = yaml.safe_load(content)
    except yaml.YAMLError as error:
        raise CompatibilityError(f"cannot parse {origin}") from error
    expected = {
        "apiVersion": "kustomize.config.k8s.io/v1beta1",
        "kind": "Kustomization",
        "resources": resources,
    }
    if document != expected:
        raise CompatibilityError(
            f"{origin} must remain transform-free with the canonical resources"
        )


def parse_flux_sync(content: str, *, origin: str) -> list[dict[str, Any]]:
    """Require the generated bootstrap source and self-Kustomization contract."""
    try:
        documents = [document for document in yaml.safe_load_all(content) if document]
    except yaml.YAMLError as error:
        raise CompatibilityError(f"cannot parse {origin}") from error
    if len(documents) != 2:
        raise CompatibilityError(f"{origin} must contain exactly two resources")
    try:
        source_url = documents[0]["spec"]["url"]
    except (KeyError, TypeError) as error:
        raise CompatibilityError(
            f"{origin} is missing its client source URL"
        ) from error
    if (
        not isinstance(source_url, str)
        or CLIENT_SOURCE_URL_PATTERN.fullmatch(source_url) is None
    ):
        raise CompatibilityError(f"{origin} must use the canonical client source URL")
    expected = [
        {
            "apiVersion": "source.toolkit.fluxcd.io/v1",
            "kind": "GitRepository",
            "metadata": {"name": "flux-system", "namespace": "flux-system"},
            "spec": {
                "interval": "1m0s",
                "ref": {"branch": "main"},
                "secretRef": {"name": "flux-system"},
                "url": source_url,
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
    if documents != expected:
        raise CompatibilityError(f"{origin} must retain the canonical bootstrap spec")
    return documents


def read_control_plane_contract(
    root: Path,
    revision: str,
    revision_reader: Callable[[Path, str, Path], str],
) -> tuple[list[dict[str, Any]], str]:
    """Read and validate composition controls from one explicit revision."""
    parse_kustomization(
        revision_reader(root, revision, CLUSTER_KUSTOMIZATION_PATH),
        origin=f"{revision} cluster Kustomization",
        resources=CLUSTER_RESOURCES,
    )
    parse_kustomization(
        revision_reader(root, revision, FLUX_KUSTOMIZATION_PATH),
        origin=f"{revision} Flux bootstrap Kustomization",
        resources=FLUX_RESOURCES,
    )
    sync = parse_flux_sync(
        revision_reader(root, revision, FLUX_SYNC_PATH),
        origin=f"{revision} Flux bootstrap sync",
    )
    components = revision_reader(root, revision, FLUX_COMPONENTS_PATH)
    return sync, components


def read_at_revision(root: Path, revision: str, path: Path) -> str:
    """Read a client file from an exact, already-fetched commit."""
    if SHA_PATTERN.fullmatch(revision) is None:
        raise CompatibilityError("revision must be a full hexadecimal Git object ID")
    object_name = f"{revision}:{path.as_posix()}"
    size_text = run_command(["git", "cat-file", "-s", object_name], cwd=root).strip()
    try:
        size = int(size_text)
    except ValueError as error:
        raise CompatibilityError(
            f"cannot determine size of {path.as_posix()}"
        ) from error
    if size > MAX_REVISION_FILE_BYTES:
        raise CompatibilityError(
            f"{path.as_posix()} exceeds the {MAX_REVISION_FILE_BYTES}-byte review limit"
        )
    return run_command(["git", "show", object_name], cwd=root)


def source_ignore_paths(root: Path, revision: str) -> list[str]:
    """Return every source-controller ignore file in one exact Git tree."""
    if SHA_PATTERN.fullmatch(revision) is None:
        raise CompatibilityError("revision must be a full hexadecimal Git object ID")
    output = run_command(
        ["git", "ls-tree", "-r", "-z", "--name-only", revision],
        cwd=root,
    )
    return [
        path
        for path in output.split("\0")
        if path.rsplit("/", 1)[-1] == ".sourceignore"
    ]


def fetch_pull_request_refs(
    root: Path,
    pull_request_number: int,
    base_sha: str,
    head_sha: str,
    merge_sha: str,
) -> None:
    """Fetch a PR as data and verify its exact base, head, and test-merge tuple."""
    if pull_request_number < 1:
        raise CompatibilityError("pull-request number must be a positive integer")
    for name, sha in (("base", base_sha), ("head", head_sha), ("merge", merge_sha)):
        if SHA_PATTERN.fullmatch(sha) is None:
            raise CompatibilityError(
                f"{name} SHA must be a full hexadecimal Git object ID"
            )
    head_ref = "refs/platform-compatibility/pull-request-head"
    merge_ref = "refs/platform-compatibility/pull-request-merge"
    run_command(
        [
            "git",
            "fetch",
            "--quiet",
            "--no-tags",
            "--depth=2",
            "origin",
            f"+refs/pull/{pull_request_number}/head:{head_ref}",
            f"+refs/pull/{pull_request_number}/merge:{merge_ref}",
        ],
        cwd=root,
    )
    fetched_head = run_command(["git", "rev-parse", head_ref], cwd=root).strip()
    fetched_merge = run_command(["git", "rev-parse", merge_ref], cwd=root).strip()
    if fetched_head != head_sha:
        raise CompatibilityError(
            f"fetched pull-request head {fetched_head!r} does not match event SHA"
        )
    if fetched_merge != merge_sha:
        raise CompatibilityError(
            f"fetched pull-request merge {fetched_merge!r} does not match API SHA"
        )
    parents = run_command(
        ["git", "rev-list", "--parents", "-n", "1", merge_ref], cwd=root
    ).split()
    if parents != [merge_sha, base_sha, head_sha]:
        raise CompatibilityError(
            "pull-request test merge must have the exact current base and head parents"
        )


def fetch_base_revision(selector: str, revision: str) -> str:
    """Resolve one allowed Base branch or peeled tag to a full commit SHA."""
    if (selector, revision) == ("branch", "main"):
        reference = "refs/heads/main"
    elif selector == "commit" and COMMIT_SHA_PATTERN.fullmatch(revision):
        return revision
    elif selector == "tag":
        parse_tag(revision, field="Base tag revision")
        reference = f"refs/tags/{revision}^{{}}"
    else:
        raise CompatibilityError(f"unsupported Base selector: {selector}:{revision}")
    output = run_command(["git", "ls-remote", PLATFORM_SOURCE_URL, reference]).split()
    if len(output) != 2 or COMMIT_SHA_PATTERN.fullmatch(output[0]) is None:
        raise CompatibilityError(f"cannot resolve Base {selector} {revision}")
    return output[0]


def is_base_ancestor(ancestor: str, descendant: str) -> bool:
    """Return whether one Base commit is an ancestor of another."""
    for name, revision in (("ancestor", ancestor), ("descendant", descendant)):
        if COMMIT_SHA_PATTERN.fullmatch(revision) is None:
            raise CompatibilityError(f"{name} must be a full 40-hex commit SHA")
    with tempfile.TemporaryDirectory(prefix="platform-ancestry-") as temporary:
        repository = Path(temporary) / "base"
        repository.mkdir()
        run_command(["git", "init", "--quiet"], cwd=repository)
        run_command(
            ["git", "remote", "add", "origin", PLATFORM_SOURCE_URL], cwd=repository
        )
        run_command(
            [
                "git",
                "fetch",
                "--quiet",
                "--no-tags",
                "origin",
                ancestor,
                descendant,
            ],
            cwd=repository,
        )
        try:
            result = subprocess.run(
                ["git", "merge-base", "--is-ancestor", ancestor, descendant],
                cwd=repository,
                check=False,
                capture_output=True,
                text=True,
                timeout=COMMAND_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as error:
            raise CompatibilityError(
                "Base ancestry comparison timed out after "
                f"{COMMAND_TIMEOUT_SECONDS} seconds"
            ) from error
        if result.returncode == 0:
            return True
        if result.returncode == 1:
            return False
        detail = (result.stderr or result.stdout).strip()
        raise CompatibilityError(f"cannot compare Base revisions: {detail[:1000]}")


def fetch_and_verify_tag(tag: str, expected_fingerprint: str) -> VerifiedTag:
    """Fetch a tag, verify its signature, and expose its peeled commit."""
    with tempfile.TemporaryDirectory(prefix="platform-release-") as temporary:
        repository = Path(temporary) / "base"
        repository.mkdir()
        run_command(["git", "init", "--quiet"], cwd=repository)
        run_command(
            ["git", "remote", "add", "origin", PLATFORM_SOURCE_URL], cwd=repository
        )
        run_command(
            [
                "git",
                "fetch",
                "--quiet",
                "--no-tags",
                "--depth=1",
                "origin",
                f"refs/tags/{tag}:refs/tags/{tag}",
            ],
            cwd=repository,
        )

        tag_ref = f"refs/tags/{tag}"
        if (
            run_command(["git", "cat-file", "-t", tag_ref], cwd=repository).strip()
            != "tag"
        ):
            raise CompatibilityError(f"{tag} is not an annotated tag")

        public_key = run_command(
            ["git", "show", f"{tag_ref}:{TRUST_KEY_PATH}"], cwd=repository
        ).strip()
        key_parts = public_key.split()
        if len(key_parts) < 2 or key_parts[0] != "ssh-ed25519":
            raise CompatibilityError(
                f"{tag} contains an invalid platform release public key"
            )

        key_file = Path(temporary) / "platform-release.sshpub"
        key_file.write_text(f"{public_key}\n", encoding="utf-8")
        fingerprint_output = run_command(
            ["ssh-keygen", "-lf", str(key_file), "-E", "sha256"]
        ).split()
        actual_fingerprint = (
            fingerprint_output[1] if len(fingerprint_output) > 1 else ""
        )
        if actual_fingerprint != expected_fingerprint:
            raise CompatibilityError(
                f"{tag} signer fingerprint {actual_fingerprint!r} does not match the "
                "out-of-band trusted fingerprint"
            )

        allowed_signers = Path(temporary) / "allowed_signers"
        allowed_signers.write_text(
            f"platform-release {key_parts[0]} {key_parts[1]}\n", encoding="utf-8"
        )
        run_command(
            [
                "git",
                "-c",
                f"gpg.ssh.allowedSignersFile={allowed_signers}",
                "verify-tag",
                tag_ref,
            ],
            cwd=repository,
        )

        manifest = run_command(
            ["git", "show", f"{tag_ref}:release/manifest.yaml"], cwd=repository
        )
        migration = run_command(
            ["git", "show", f"{tag_ref}:release/migrations/{tag}.md"], cwd=repository
        )
        commit = run_command(
            ["git", "rev-parse", f"{tag_ref}^{{commit}}"], cwd=repository
        ).strip()
        if COMMIT_SHA_PATTERN.fullmatch(commit) is None:
            raise CompatibilityError(f"{tag} did not peel to a full commit SHA")
        return VerifiedTag(manifest=manifest, migration=migration, commit=commit)


def fetch_release(tag: str, token: str | None) -> dict[str, Any]:
    """Fetch the published GitHub Release associated with an exact tag."""
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
        "User-Agent": "neurwerk-client-platform-compatibility",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(f"{PLATFORM_RELEASE_API}{quote(tag, safe='')}", headers=headers)
    try:
        with urlopen(request, timeout=20) as response:  # noqa: S310 - fixed GitHub API
            payload = json.load(response)
    except HTTPError as error:
        raise CompatibilityError(
            f"GitHub Release lookup for {tag} failed with HTTP {error.code}"
        ) from error
    except (URLError, TimeoutError, json.JSONDecodeError) as error:
        raise CompatibilityError(
            f"GitHub Release lookup for {tag} failed: {error}"
        ) from error
    if not isinstance(payload, dict):
        raise CompatibilityError(
            f"GitHub Release lookup for {tag} returned invalid data"
        )
    return payload


def migration_sections(migration: str, tag: str) -> dict[str, str]:
    """Parse required level-two migration sections and reject omissions."""
    if not migration.startswith(f"# Platform {tag}\n"):
        raise CompatibilityError(f"migration title must agree with {tag}")
    matches = list(re.finditer(r"^## (.+?)\s*$", migration, flags=re.MULTILINE))
    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(migration)
        heading = match.group(1)
        if heading in sections:
            raise CompatibilityError(f"migration contains duplicate heading: {heading}")
        sections[heading] = migration[match.end() : end].strip()
    missing = sorted(MANDATORY_MIGRATION_HEADINGS - set(sections))
    if missing:
        raise CompatibilityError(
            f"migration is missing mandatory headings: {', '.join(missing)}"
        )
    return sections


def parse_support_contract(support: str) -> tuple[set[str] | str, str]:
    """Parse either the legacy source allowlist or the stable upgrade policy."""

    downgrade_matches = re.findall(
        r"^- Downgrade: (.+)\.$", support, flags=re.MULTILINE
    )
    if len(downgrade_matches) != 1:
        raise CompatibilityError(
            "migration Support must contain exactly one downgrade declaration"
        )
    try:
        downgrade = COMPATIBILITY_DISPLAY_VALUES[downgrade_matches[0]]
    except KeyError as error:
        raise CompatibilityError(
            "migration downgrade must be Supported or Unsupported"
        ) from error

    stable_matches = re.findall(
        r"^- Stable upgrades: (.+)\.$", support, flags=re.MULTILINE
    )
    source_matches = re.findall(
        r"^- Supported source versions: (.+)\.$", support, flags=re.MULTILINE
    )
    if len(stable_matches) + len(source_matches) != 1:
        raise CompatibilityError(
            "migration Support must contain exactly one Stable upgrades or legacy "
            "Supported source versions declaration"
        )
    if stable_matches:
        try:
            return STABLE_UPGRADE_DISPLAY_VALUES[stable_matches[0]], downgrade
        except KeyError as error:
            raise CompatibilityError(
                "migration stable upgrades must be Supported or Fresh installation only"
            ) from error

    declaration = source_matches[0]
    if declaration == "None":
        sources: list[str] = []
    else:
        sources = []
        for item in declaration.split(","):
            match = re.fullmatch(r"`([^`]+)`", item.strip())
            if match is None:
                raise CompatibilityError(
                    "Supported source versions must be None or comma-separated exact "
                    "`vX.Y.Z` tags"
                )
            source_tag = match.group(1)
            parse_tag(source_tag, field="migration supported source version")
            sources.append(source_tag)
    if len(sources) != len(set(sources)):
        raise CompatibilityError(
            "migration supported source versions contain duplicates"
        )
    return set(sources), downgrade


def parse_recovery_contract(recovery: str) -> str:
    """Parse and normalize the exact recovery classification declaration."""
    matches = re.findall(
        r"^Recovery classification: (.+)\.$", recovery, flags=re.MULTILINE
    )
    if len(matches) != 1:
        raise CompatibilityError(
            "migration Recovery must contain exactly one recovery classification "
            "declaration"
        )
    try:
        return RECOVERY_DISPLAY_VALUES[matches[0]]
    except KeyError as error:
        known = ", ".join(RECOVERY_DISPLAY_VALUES)
        raise CompatibilityError(
            f"migration recovery classification must be one of: {known}"
        ) from error


def parse_alpha_source_revisions(support: str) -> set[str] | None:
    """Parse the optional exact alpha promotion declaration from Support."""
    prefix = "- Supported alpha source revisions: "
    declarations = [
        line.removeprefix(prefix)
        for line in support.splitlines()
        if line.startswith(prefix)
    ]
    if not declarations:
        return None
    if len(declarations) != 1 or not declarations[0].endswith("."):
        raise CompatibilityError(
            "migration Support must contain exactly one '- Supported alpha source "
            "revisions:' declaration"
        )
    value = declarations[0][:-1]
    if value == "None":
        return set()
    revisions: list[str] = []
    for item in value.split(","):
        match = re.fullmatch(r"`([0-9a-f]{40})`", item.strip())
        if match is None:
            raise CompatibilityError(
                "Supported alpha source revisions must be None or comma-separated "
                "full 40-hex SHAs in backticks"
            )
        revisions.append(match.group(1))
    if len(revisions) != len(set(revisions)):
        raise CompatibilityError("Supported alpha source revisions contain duplicates")
    return set(revisions)


def validate_alpha_promotion_contract(
    source_revision: str,
    target: PlatformSource,
    verified_tag: VerifiedTag,
    release: dict[str, Any],
    expected_fingerprint: str,
    *,
    forward: bool,
) -> None:
    """Validate an authenticated stable target promoted from alpha."""
    tag = target.revision
    validate_release_contract(
        tag,
        tag,
        verified_tag.manifest,
        verified_tag.migration,
        release,
        target.adoption_mode or "",
        expected_fingerprint,
        validate_transition=False,
    )
    try:
        manifest = yaml.safe_load(verified_tag.manifest)
        compatibility = manifest["spec"]["compatibility"]
    except (TypeError, KeyError, yaml.YAMLError) as error:
        raise CompatibilityError(f"{tag} release manifest is malformed") from error
    sections = migration_sections(verified_tag.migration, tag)
    manifest_revisions: set[str] | None = None
    if "upgradesFromAlphaRevisions" in compatibility:
        revisions = compatibility["upgradesFromAlphaRevisions"]
        if not isinstance(revisions, list) or not all(
            isinstance(revision, str) and COMMIT_SHA_PATTERN.fullmatch(revision)
            for revision in revisions
        ):
            raise CompatibilityError(
                "manifest compatibility.upgradesFromAlphaRevisions must be a list of "
                "full 40-hex SHAs"
            )
        if len(revisions) != len(set(revisions)):
            raise CompatibilityError(
                "manifest compatibility.upgradesFromAlphaRevisions contains duplicates"
            )
        manifest_revisions = set(revisions)
    migration_revisions = parse_alpha_source_revisions(sections["Support"])
    if manifest_revisions != migration_revisions:
        raise CompatibilityError(
            "migration Supported alpha source revisions must exactly equal manifest "
            "upgradesFromAlphaRevisions"
        )
    if target.adoption_mode == "fresh-install":
        return
    if not forward:
        return
    if manifest_revisions is None:
        raise CompatibilityError(
            "forward alpha upgrade requires upgradesFromAlphaRevisions and the "
            "Supported alpha source revisions migration declaration"
        )
    if source_revision not in manifest_revisions:
        raise CompatibilityError(
            "target manifest does not list the exact promoted alpha source revision"
        )


def validate_release_contract(
    old_tag: str,
    new_tag: str,
    manifest_text: str,
    migration: str,
    release: dict[str, Any],
    adoption_mode: str,
    expected_fingerprint: str,
    *,
    validate_transition: bool = True,
) -> None:
    """Validate version, release, compatibility, and migration agreement."""
    new_version = parse_tag(new_tag, field="proposed platform pin")
    if validate_transition:
        old_version = parse_tag(old_tag, field="base platform pin")
        if new_version <= old_version:
            direction = "unchanged" if new_version == old_version else "a downgrade"
            raise CompatibilityError(
                f"platform transition is {direction}: {old_tag} -> {new_tag}"
            )

    try:
        manifest = yaml.safe_load(manifest_text)
        spec = manifest["spec"]
        compatibility = spec["compatibility"]
        trust = spec["trust"]
    except (TypeError, KeyError, yaml.YAMLError) as error:
        raise CompatibilityError(f"{new_tag} release manifest is malformed") from error

    if manifest.get("apiVersion") != "platform.neurwerk.com/v1alpha1":
        raise CompatibilityError("manifest apiVersion is not supported")
    if manifest.get("kind") != "PlatformRelease":
        raise CompatibilityError("manifest kind is not PlatformRelease")
    if manifest.get("metadata", {}).get("name") != new_tag:
        raise CompatibilityError("manifest metadata.name does not agree with the tag")
    if str(spec.get("version")) != new_tag.removeprefix("v"):
        raise CompatibilityError("manifest spec.version does not agree with the tag")
    if trust.get("algorithm") != "ssh-ed25519":
        raise CompatibilityError("manifest signer algorithm is not ssh-ed25519")
    if trust.get("fingerprint") != expected_fingerprint:
        raise CompatibilityError(
            "manifest signer fingerprint does not match the out-of-band trusted "
            "fingerprint"
        )

    legacy = "upgradesFrom" in compatibility
    if legacy:
        if new_tag not in LEGACY_UPGRADES_FROM_TARGETS:
            raise CompatibilityError(
                "manifest compatibility.upgradesFrom is legacy and allowed only for "
                "published targets v0.1.0 and v0.1.1"
            )
        if "stableUpgrade" in compatibility:
            raise CompatibilityError(
                "manifest compatibility must not combine upgradesFrom and stableUpgrade"
            )
        upgrades_from = compatibility["upgradesFrom"]
        if not isinstance(upgrades_from, list) or not all(
            isinstance(version, str) for version in upgrades_from
        ):
            raise CompatibilityError(
                "manifest compatibility.upgradesFrom must be a list of tags"
            )
        for index, version in enumerate(upgrades_from):
            parse_tag(version, field=f"manifest upgradesFrom[{index}]")
        supported_sources = set(upgrades_from)
    else:
        stable_upgrade = compatibility.get("stableUpgrade")
        if stable_upgrade not in set(STABLE_UPGRADE_DISPLAY_VALUES.values()):
            raise CompatibilityError(
                "manifest compatibility.stableUpgrade must be supported or "
                "fresh-install-only"
            )
    downgrade = compatibility.get("downgrade")
    if downgrade not in set(COMPATIBILITY_DISPLAY_VALUES.values()):
        raise CompatibilityError("manifest downgrade must be supported or unsupported")
    recovery = compatibility.get("recovery")
    if recovery not in set(RECOVERY_DISPLAY_VALUES.values()):
        raise CompatibilityError("manifest recovery classification is not supported")

    if release.get("tag_name") != new_tag:
        raise CompatibilityError(
            "GitHub Release tag does not agree with the proposed pin"
        )
    if release.get("draft") is not False or release.get("prerelease") is not False:
        raise CompatibilityError(
            "target GitHub Release must be published, non-draft, and full"
        )
    if not release.get("published_at"):
        raise CompatibilityError("target GitHub Release is not published")

    sections = migration_sections(migration, new_tag)
    if not legacy and "Breaking Changes" not in sections:
        raise CompatibilityError(
            "migration is missing mandatory heading: Breaking Changes"
        )
    migration_stable_support, migration_downgrade = parse_support_contract(
        sections["Support"]
    )
    migration_recovery = parse_recovery_contract(sections["Recovery"])
    if legacy:
        if migration_stable_support != supported_sources:
            raise CompatibilityError(
                "migration Supported source versions must exactly equal manifest "
                "upgradesFrom"
            )
    else:
        if migration_stable_support != stable_upgrade:
            raise CompatibilityError(
                "migration Stable upgrades must agree with manifest stableUpgrade"
            )
    if migration_downgrade != downgrade:
        raise CompatibilityError(
            "migration downgrade support disagrees with the manifest"
        )
    if migration_recovery != recovery:
        raise CompatibilityError(
            "migration recovery classification disagrees with the manifest"
        )
    if downgrade != "unsupported":
        raise CompatibilityError(
            "manifest must explicitly mark downgrade as unsupported"
        )

    if not validate_transition:
        return
    if adoption_mode == "upgrade":
        if legacy and old_tag not in supported_sources:
            raise CompatibilityError(
                f"{new_tag} does not support an upgrade from {old_tag}"
            )
        if not legacy and stable_upgrade != "supported":
            raise CompatibilityError(
                f"{new_tag} supports fresh installation only, not stable upgrades"
            )
        return
    if adoption_mode != "fresh-install":
        known = ", ".join(sorted(ADOPTION_MODES))
        raise CompatibilityError(f"platform adoption mode must be one of: {known}")


def run_check(
    root: Path,
    base_sha: str,
    proposed_sha: str,
    expected_fingerprint: str,
    github_token: str | None,
    *,
    classify_only: bool = False,
    expected_old_alpha_commit: str | None = None,
    expected_new_alpha_commit: str | None = None,
    revision_reader: Callable[[Path, str, Path], str] = read_at_revision,
    source_ignore_finder: Callable[[Path, str], list[str]] = source_ignore_paths,
    tag_fetcher: Callable[[str, str], VerifiedTag] = fetch_and_verify_tag,
    release_fetcher: Callable[[str, str | None], dict[str, Any]] = fetch_release,
    base_revision_fetcher: Callable[[str, str], str] = fetch_base_revision,
    ancestor_checker: Callable[[str, str], bool] = is_base_ancestor,
) -> CheckResult:
    """Classify or verify a transition using only explicit Git revisions."""
    for revision in (base_sha, proposed_sha):
        ignored_paths = source_ignore_finder(root, revision)
        if ignored_paths:
            raise CompatibilityError(
                f"{revision} contains prohibited source-controller ignore files: "
                f"{', '.join(ignored_paths)}"
            )
    base_content = revision_reader(root, base_sha, PLATFORM_SOURCE_PATH)
    proposed_content = revision_reader(root, proposed_sha, PLATFORM_SOURCE_PATH)
    old_source = parse_platform_source(
        base_content, origin=f"base {base_sha}"
    )
    new_source = parse_platform_source(
        proposed_content, origin=f"proposed {proposed_sha}"
    )
    base_control_plane = read_control_plane_contract(root, base_sha, revision_reader)
    proposed_control_plane = read_control_plane_contract(
        root, proposed_sha, revision_reader
    )
    if proposed_control_plane != base_control_plane:
        raise CompatibilityError(
            "Flux bootstrap controls may not change in a platform adoption pull request"
        )
    if (
        old_source.channel == "alpha"
        and old_source.selector == "branch"
        and new_source.channel == "stable"
    ):
        raise CompatibilityError(
            "alpha branch cannot transition directly to stable; freeze the source to "
            "the observed alpha commit and reconcile it first"
        )
    resolved_revisions: dict[tuple[str, str], str] = {}

    def validated_commit(value: str, field: str) -> str:
        if COMMIT_SHA_PATTERN.fullmatch(value) is None:
            raise CompatibilityError(f"{field} must resolve to a full 40-hex commit SHA")
        return value

    def resolve(selector: str, revision: str) -> str:
        key = (selector, revision)
        if key not in resolved_revisions:
            resolved_revisions[key] = validated_commit(
                base_revision_fetcher(selector, revision),
                f"Base {selector}:{revision}",
            )
        return resolved_revisions[key]

    def resolve_alpha(source: PlatformSource) -> str | None:
        if source.channel != "alpha":
            return None
        if source.selector == "branch":
            return resolve("branch", "main")
        pinned_commit = resolve("commit", source.revision)
        main_commit = resolve("branch", "main")
        if pinned_commit != main_commit and not ancestor_checker(
            pinned_commit, main_commit
        ):
            raise CompatibilityError(
                "alpha commit must be equal to or an ancestor of protected Base main"
            )
        return pinned_commit

    old_alpha_commit = resolve_alpha(old_source)
    new_alpha_commit = resolve_alpha(new_source)
    for name, expected, actual in (
        ("old", expected_old_alpha_commit, old_alpha_commit),
        ("new", expected_new_alpha_commit, new_alpha_commit),
    ):
        if expected is not None:
            if COMMIT_SHA_PATTERN.fullmatch(expected) is None:
                raise CompatibilityError(
                    f"expected {name} alpha commit must be a full 40-hex SHA"
                )
            if actual != expected:
                raise CompatibilityError(
                    f"resolved {name} alpha commit changed from {expected} to {actual}"
                )

    changed = old_source != new_source
    if old_source.channel == "alpha" and new_source.channel == "alpha":
        assert old_alpha_commit is not None
        assert new_alpha_commit is not None
        if (
            old_source.selector == "branch"
            and new_source.selector == "commit"
            and old_alpha_commit != new_alpha_commit
        ):
            raise CompatibilityError(
                "alpha freeze commit must exactly equal the resolved protected Base "
                "main revision"
            )
        if (
            old_source.selector == "commit"
            and new_source.selector == "commit"
            and old_alpha_commit != new_alpha_commit
            and not ancestor_checker(old_alpha_commit, new_alpha_commit)
        ):
            raise CompatibilityError("alpha commit source may not move backward or diverge")
        return CheckResult(
            old_source,
            new_source,
            old_alpha_commit,
            new_alpha_commit,
            changed=changed,
            verified=changed and not classify_only,
        )

    if old_source.channel == "stable" and new_source.channel == "stable":
        if FINGERPRINT_PATTERN.fullmatch(expected_fingerprint) is None:
            raise CompatibilityError(
                "PLATFORM_RELEASE_SIGNER_FINGERPRINT is missing or invalid; configure "
                "the out-of-band trusted SHA256 fingerprint as a GitHub Actions "
                "repository variable"
            )
        if old_source.revision == new_source.revision:
            if old_source != new_source:
                raise CompatibilityError(
                    "stable source annotations may change only with the exact platform tag"
                )
            return CheckResult(
                old_source,
                new_source,
                old_alpha_commit,
                new_alpha_commit,
                changed=False,
                verified=False,
            )
        if new_source.promoted_from_alpha is not None:
            raise CompatibilityError(
                f"{PROMOTED_FROM_ALPHA_ANNOTATION} is valid only for alpha-to-stable "
                "transitions"
            )
        if parse_tag(new_source.revision, field="proposed platform pin") < parse_tag(
            old_source.revision, field="base platform pin"
        ):
            raise CompatibilityError(
                "platform downgrade is prohibited: "
                f"{old_source.revision} -> {new_source.revision}"
            )
        if classify_only:
            return CheckResult(
                old_source,
                new_source,
                old_alpha_commit,
                new_alpha_commit,
                changed=True,
                verified=False,
            )
        verified_tag = tag_fetcher(new_source.revision, expected_fingerprint)
        release = release_fetcher(new_source.revision, github_token)
        validate_release_contract(
            old_source.revision,
            new_source.revision,
            verified_tag.manifest,
            verified_tag.migration,
            release,
            new_source.adoption_mode or "",
            expected_fingerprint,
        )
        return CheckResult(
            old_source,
            new_source,
            old_alpha_commit,
            new_alpha_commit,
            changed=True,
            verified=True,
        )

    if old_source.channel == "stable" and new_source.channel == "alpha":
        if FINGERPRINT_PATTERN.fullmatch(expected_fingerprint) is None:
            raise CompatibilityError(
                "PLATFORM_RELEASE_SIGNER_FINGERPRINT is missing or invalid; configure "
                "the out-of-band trusted SHA256 fingerprint as a GitHub Actions "
                "repository variable"
            )
        verified_baseline = tag_fetcher(old_source.revision, expected_fingerprint)
        baseline_commit = validated_commit(
            verified_baseline.commit, "authenticated stable tag"
        )
        assert new_alpha_commit is not None
        if baseline_commit != new_alpha_commit and not ancestor_checker(
            baseline_commit, new_alpha_commit
        ):
            raise CompatibilityError(
                "selected alpha revision is behind or divergent from the authenticated "
                "stable release"
            )
        return CheckResult(
            old_source,
            new_source,
            old_alpha_commit,
            new_alpha_commit,
            changed=True,
            verified=not classify_only,
        )

    if FINGERPRINT_PATTERN.fullmatch(expected_fingerprint) is None:
        raise CompatibilityError(
            "PLATFORM_RELEASE_SIGNER_FINGERPRINT is missing or invalid; configure the "
            "out-of-band trusted SHA256 fingerprint as a GitHub Actions repository "
            "variable"
        )
    assert old_alpha_commit is not None
    observed_revision = old_alpha_commit
    if new_source.promoted_from_alpha != observed_revision:
        raise CompatibilityError(
            f"{PROMOTED_FROM_ALPHA_ANNOTATION} must equal the exact observed Base main "
            f"revision {observed_revision}"
        )
    if classify_only:
        target_commit = resolve(new_source.selector, new_source.revision)
        verified_tag = None
    else:
        verified_tag = tag_fetcher(new_source.revision, expected_fingerprint)
        target_commit = validated_commit(verified_tag.commit, "authenticated stable tag")
    exact_commit = target_commit == observed_revision
    if not exact_commit and not ancestor_checker(observed_revision, target_commit):
        raise CompatibilityError(
            "stable target is behind or divergent from the observed alpha revision"
        )
    if classify_only:
        return CheckResult(
            old_source,
            new_source,
            old_alpha_commit,
            new_alpha_commit,
            changed=True,
            verified=False,
        )
    assert verified_tag is not None
    release = release_fetcher(new_source.revision, github_token)
    validate_alpha_promotion_contract(
        observed_revision,
        new_source,
        verified_tag,
        release,
        expected_fingerprint,
        forward=not exact_commit,
    )
    return CheckResult(
        old_source,
        new_source,
        old_alpha_commit,
        new_alpha_commit,
        changed=True,
        verified=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--merge-sha")
    parser.add_argument("--pull-request-number", type=int)
    parser.add_argument("--classify-only", action="store_true")
    parser.add_argument("--expected-old-alpha-commit")
    parser.add_argument("--expected-new-alpha-commit")
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    arguments = parser.parse_args()
    try:
        root = arguments.root.resolve()
        if arguments.pull_request_number is not None:
            if arguments.merge_sha is None:
                raise CompatibilityError(
                    "merge SHA is required when a pull-request number is supplied"
                )
            fetch_pull_request_refs(
                root,
                arguments.pull_request_number,
                arguments.base_sha,
                arguments.head_sha,
                arguments.merge_sha,
            )
        proposed_sha = arguments.merge_sha or arguments.head_sha
        result = run_check(
            root,
            arguments.base_sha,
            proposed_sha,
            os.environ.get("PLATFORM_RELEASE_SIGNER_FINGERPRINT", ""),
            os.environ.get("GITHUB_TOKEN"),
            classify_only=arguments.classify_only,
            expected_old_alpha_commit=arguments.expected_old_alpha_commit or None,
            expected_new_alpha_commit=arguments.expected_new_alpha_commit or None,
        )
    except (CompatibilityError, OSError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    if arguments.github_output is not None:
        with arguments.github_output.open("a", encoding="utf-8") as output:
            output.write(f"old_source_channel={result.old_source.channel}\n")
            output.write(f"old_source_selector={result.old_source.selector}\n")
            output.write(f"old_source_revision={result.old_source.revision}\n")
            output.write(f"new_source_channel={result.new_source.channel}\n")
            output.write(f"new_source_selector={result.new_source.selector}\n")
            output.write(f"new_source_revision={result.new_source.revision}\n")
            output.write(f"old_alpha_commit={result.old_alpha_commit or ''}\n")
            output.write(f"new_alpha_commit={result.new_alpha_commit or ''}\n")
            output.write(
                f"adoption_mode={result.new_source.adoption_mode or 'not-applicable'}\n"
            )
            output.write(f"platform_source_changed={str(result.changed).lower()}\n")
            output.write(f"platform_verified={str(result.verified).lower()}\n")
    old_display = (
        f"{result.old_source.channel} "
        f"{result.old_source.selector}:{result.old_source.revision}"
    )
    new_display = (
        f"{result.new_source.channel} "
        f"{result.new_source.selector}:{result.new_source.revision}"
    )
    if result.changed and result.verified:
        print(f"verified compatible platform transition {old_display} -> {new_display}")
    elif result.changed:
        print(f"platform source change classified: {old_display} -> {new_display}")
    else:
        print(f"platform source unchanged at {new_display}; release verification skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
