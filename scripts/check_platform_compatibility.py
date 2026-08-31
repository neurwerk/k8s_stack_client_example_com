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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

import yaml

PLATFORM_SOURCE_PATH = Path("clusters/prod-eu-1/platform-source.yaml")
PLATFORM_SOURCE_URL = "https://github.com/neurwerk/k8s_stack_base.git"
PLATFORM_RELEASE_API = (
    "https://api.github.com/repos/neurwerk/k8s_stack_base/releases/tags/"
)
TRUST_KEY_PATH = "release/trust/platform-release.sshpub"
FRESH_INSTALL_LABEL = "platform: fresh-install"
TAG_PATTERN = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
BARE_SEMVER_PATTERN = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
FINGERPRINT_PATTERN = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
SHA_PATTERN = re.compile(r"^[0-9a-f]{40,64}$")
LEGACY_BARE_UPGRADES_FROM_RANGE = ((0, 2, 1), (0, 2, 5))
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


class CompatibilityError(RuntimeError):
    """A platform transition failed a required review gate."""


@dataclass(frozen=True)
class CheckResult:
    """Machine-readable platform-pin classification and verification result."""

    old_tag: str
    new_tag: str
    changed: bool
    verified: bool


def run_command(arguments: list[str], *, cwd: Path | None = None) -> str:
    """Run a local command and return stdout with a bounded failure message."""
    result = subprocess.run(
        arguments,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )
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


def parse_platform_source(content: str, *, origin: str) -> str:
    """Return the exact tag from a valid public, verified Flux source."""
    try:
        source = yaml.safe_load(content)
        spec = source["spec"]
        reference = spec["ref"]
    except (TypeError, KeyError, yaml.YAMLError) as error:
        raise CompatibilityError(f"cannot parse platform source from {origin}") from error

    if spec.get("url") != PLATFORM_SOURCE_URL:
        raise CompatibilityError(f"{origin} must use public source {PLATFORM_SOURCE_URL}")
    if set(reference) != {"tag"}:
        raise CompatibilityError(f"{origin} must select exactly one tag")
    if spec.get("verify", {}).get("mode") != "Tag":
        raise CompatibilityError(f"{origin} must retain Flux tag verification")
    trust_name = spec.get("verify", {}).get("secretRef", {}).get("name")
    if trust_name != "k8s-stack-release-trust":
        raise CompatibilityError(
            f"{origin} must use trust Secret k8s-stack-release-trust"
        )

    tag = reference["tag"]
    parse_tag(tag, field=f"{origin} platform pin")
    return tag


def read_at_revision(root: Path, revision: str, path: Path) -> str:
    """Read a client file from an exact, already-fetched commit."""
    if SHA_PATTERN.fullmatch(revision) is None:
        raise CompatibilityError("revision must be a full hexadecimal Git object ID")
    return run_command(["git", "show", f"{revision}:{path.as_posix()}"], cwd=root)


def fetch_pull_request_head(root: Path, pull_request_number: int, head_sha: str) -> None:
    """Fetch a PR head only as Git data and verify its immutable event SHA."""
    if pull_request_number < 1:
        raise CompatibilityError("pull-request number must be a positive integer")
    if SHA_PATTERN.fullmatch(head_sha) is None:
        raise CompatibilityError("head SHA must be a full hexadecimal Git object ID")
    local_ref = "refs/platform-compatibility/pull-request-head"
    run_command(
        [
            "git",
            "fetch",
            "--quiet",
            "--no-tags",
            "--depth=1",
            "origin",
            f"+refs/pull/{pull_request_number}/head:{local_ref}",
        ],
        cwd=root,
    )
    fetched_sha = run_command(["git", "rev-parse", local_ref], cwd=root).strip()
    if fetched_sha != head_sha:
        raise CompatibilityError(
            f"fetched pull-request head {fetched_sha!r} does not match event SHA"
        )


def fetch_and_verify_tag(tag: str, expected_fingerprint: str) -> tuple[str, str]:
    """Fetch one public tag, establish trust by fingerprint, and verify its signature."""
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
        if run_command(["git", "cat-file", "-t", tag_ref], cwd=repository).strip() != "tag":
            raise CompatibilityError(f"{tag} is not an annotated tag")

        public_key = run_command(
            ["git", "show", f"{tag_ref}:{TRUST_KEY_PATH}"], cwd=repository
        ).strip()
        key_parts = public_key.split()
        if len(key_parts) < 2 or key_parts[0] != "ssh-ed25519":
            raise CompatibilityError(f"{tag} contains an invalid platform release public key")

        key_file = Path(temporary) / "platform-release.sshpub"
        key_file.write_text(f"{public_key}\n", encoding="utf-8")
        fingerprint_output = run_command(
            ["ssh-keygen", "-lf", str(key_file), "-E", "sha256"]
        ).split()
        actual_fingerprint = fingerprint_output[1] if len(fingerprint_output) > 1 else ""
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
        return manifest, migration


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
        raise CompatibilityError(f"GitHub Release lookup for {tag} failed: {error}") from error
    if not isinstance(payload, dict):
        raise CompatibilityError(f"GitHub Release lookup for {tag} returned invalid data")
    return payload


def parse_labels(labels_json: str) -> set[str]:
    """Parse authentic pull-request label names supplied by the workflow event."""
    try:
        labels = json.loads(labels_json)
    except json.JSONDecodeError as error:
        raise CompatibilityError("PR labels must be a JSON array") from error
    if not isinstance(labels, list) or not all(isinstance(label, str) for label in labels):
        raise CompatibilityError("PR labels must be a JSON array of strings")
    return set(labels)


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
        raise CompatibilityError(f"migration is missing mandatory headings: {', '.join(missing)}")
    return sections


def parse_support_contract(support: str) -> tuple[str, set[str], str]:
    """Parse the exact fresh-install, source-version, and downgrade declarations."""
    fresh_matches = re.findall(
        r"^- Fresh installation: (Supported|Unsupported)\.$",
        support,
        flags=re.MULTILINE,
    )
    if len(fresh_matches) != 1:
        raise CompatibilityError(
            "migration Support must contain exactly one fresh-install declaration"
        )

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

    source_prefix = "- Supported source versions: "
    lines = support.splitlines()
    source_indexes = [
        index for index, line in enumerate(lines) if line.startswith(source_prefix)
    ]
    if len(source_indexes) != 1:
        raise CompatibilityError(
            "migration Support must contain exactly one Supported source versions declaration"
        )
    index = source_indexes[0]
    segments = [lines[index].removeprefix(source_prefix)]
    while not segments[-1].endswith("."):
        if not segments[-1].endswith(","):
            raise CompatibilityError(
                "Supported source versions wrapped lines must end in a comma or final period"
            )
        index += 1
        if index >= len(lines) or not lines[index].startswith("  "):
            raise CompatibilityError(
                "Supported source versions continuation must use exactly two spaces"
            )
        continuation = lines[index][2:]
        if not continuation or continuation[0].isspace():
            raise CompatibilityError(
                "Supported source versions continuation must use exactly two spaces"
            )
        segments.append(continuation)
    if index + 1 < len(lines) and lines[index + 1].startswith((" ", "\t")):
        raise CompatibilityError(
            "Supported source versions has a continuation after its final period"
        )
    declaration = " ".join(segments)[:-1]
    if declaration == "None":
        sources: list[str] = []
    else:
        sources = []
        for item in declaration.split(","):
            match = re.fullmatch(r"`([^`]+)`", item.strip())
            if match is None:
                raise CompatibilityError(
                    "Supported source versions must be None or comma-separated exact `vX.Y.Z` tags"
                )
            source_tag = match.group(1)
            parse_tag(source_tag, field="migration supported source version")
            sources.append(source_tag)
    if len(sources) != len(set(sources)):
        raise CompatibilityError("migration supported source versions contain duplicates")
    return fresh_matches[0].lower(), set(sources), downgrade


def parse_recovery_contract(recovery: str) -> str:
    """Parse and normalize the exact recovery classification declaration."""
    matches = re.findall(
        r"^Recovery classification: (.+)\.$", recovery, flags=re.MULTILINE
    )
    if len(matches) != 1:
        raise CompatibilityError(
            "migration Recovery must contain exactly one recovery classification declaration"
        )
    try:
        return RECOVERY_DISPLAY_VALUES[matches[0]]
    except KeyError as error:
        known = ", ".join(RECOVERY_DISPLAY_VALUES)
        raise CompatibilityError(
            f"migration recovery classification must be one of: {known}"
        ) from error


def validate_release_contract(
    old_tag: str,
    new_tag: str,
    manifest_text: str,
    migration: str,
    release: dict[str, Any],
    labels: set[str],
    expected_fingerprint: str,
) -> None:
    """Validate version, release, compatibility, and migration agreement."""
    old_version = parse_tag(old_tag, field="base platform pin")
    new_version = parse_tag(new_tag, field="proposed platform pin")
    if new_version <= old_version:
        direction = "unchanged" if new_version == old_version else "a downgrade"
        raise CompatibilityError(f"platform transition is {direction}: {old_tag} -> {new_tag}")

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
            "manifest signer fingerprint does not match the out-of-band trusted fingerprint"
        )

    upgrades_from = compatibility.get("upgradesFrom")
    if not isinstance(upgrades_from, list) or not all(
        isinstance(version, str) for version in upgrades_from
    ):
        raise CompatibilityError("manifest compatibility.upgradesFrom must be a list of tags")
    normalized_upgrades_from: list[str] = []
    for index, version in enumerate(upgrades_from):
        if TAG_PATTERN.fullmatch(version) is not None:
            normalized = version
        elif BARE_SEMVER_PATTERN.fullmatch(version) is not None:
            minimum, maximum = LEGACY_BARE_UPGRADES_FROM_RANGE
            if not minimum <= new_version <= maximum:
                raise CompatibilityError(
                    f"manifest upgradesFrom[{index}] uses legacy bare SemVer outside "
                    "affected targets v0.2.1 through v0.2.5; exact vX.Y.Z is required"
                )
            normalized = f"v{version}"
        else:
            parse_tag(version, field=f"manifest upgradesFrom[{index}]")
            normalized = version
        normalized_upgrades_from.append(normalized)
    if len(normalized_upgrades_from) != len(set(normalized_upgrades_from)):
        raise CompatibilityError("manifest compatibility.upgradesFrom contains duplicates")
    fresh_install = compatibility.get("freshInstall")
    if fresh_install not in {"supported", "unsupported"}:
        raise CompatibilityError("manifest freshInstall must be supported or unsupported")
    downgrade = compatibility.get("downgrade")
    if downgrade not in set(COMPATIBILITY_DISPLAY_VALUES.values()):
        raise CompatibilityError("manifest downgrade must be supported or unsupported")
    recovery = compatibility.get("recovery")
    if recovery not in set(RECOVERY_DISPLAY_VALUES.values()):
        raise CompatibilityError("manifest recovery classification is not supported")

    if release.get("tag_name") != new_tag:
        raise CompatibilityError("GitHub Release tag does not agree with the proposed pin")
    if release.get("draft") is not False or release.get("prerelease") is not False:
        raise CompatibilityError("target GitHub Release must be published, non-draft, and full")
    if not release.get("published_at"):
        raise CompatibilityError("target GitHub Release is not published")

    sections = migration_sections(migration, new_tag)
    migration_fresh_install, migration_sources, migration_downgrade = (
        parse_support_contract(sections["Support"])
    )
    migration_recovery = parse_recovery_contract(sections["Recovery"])
    if migration_fresh_install != fresh_install:
        raise CompatibilityError("migration fresh-install support disagrees with the manifest")
    if migration_sources != set(normalized_upgrades_from):
        raise CompatibilityError(
            "migration Supported source versions must exactly equal manifest upgradesFrom"
        )
    if migration_downgrade != downgrade:
        raise CompatibilityError("migration downgrade support disagrees with the manifest")
    if migration_recovery != recovery:
        raise CompatibilityError("migration recovery classification disagrees with the manifest")
    if downgrade != "unsupported":
        raise CompatibilityError("manifest must explicitly mark downgrade as unsupported")

    if old_tag in normalized_upgrades_from:
        return

    if fresh_install != "supported":
        raise CompatibilityError(
            f"{new_tag} does not support upgrades from {old_tag} or fresh installation"
        )
    if FRESH_INSTALL_LABEL not in labels:
        raise CompatibilityError(
            f"{new_tag} does not list {old_tag} in upgradesFrom; fresh-install intent "
            f"requires PR label {FRESH_INSTALL_LABEL!r}. The label is not authorization"
        )


def run_check(
    root: Path,
    base_sha: str,
    head_sha: str,
    labels_json: str,
    expected_fingerprint: str,
    github_token: str | None,
    *,
    classify_only: bool = False,
    revision_reader: Callable[[Path, str, Path], str] = read_at_revision,
    tag_fetcher: Callable[[str, str], tuple[str, str]] = fetch_and_verify_tag,
    release_fetcher: Callable[[str, str | None], dict[str, Any]] = fetch_release,
) -> CheckResult:
    """Classify or verify a transition using only explicit Git revisions."""
    if FINGERPRINT_PATTERN.fullmatch(expected_fingerprint) is None:
        raise CompatibilityError(
            "PLATFORM_RELEASE_SIGNER_FINGERPRINT is missing or invalid; configure the "
            "out-of-band trusted SHA256 fingerprint as a GitHub Actions repository variable"
        )
    base_content = revision_reader(root, base_sha, PLATFORM_SOURCE_PATH)
    head_content = revision_reader(root, head_sha, PLATFORM_SOURCE_PATH)
    old_tag = parse_platform_source(base_content, origin=f"base {base_sha}")
    new_tag = parse_platform_source(head_content, origin=f"head {head_sha}")
    if old_tag == new_tag:
        return CheckResult(old_tag, new_tag, changed=False, verified=False)
    if parse_tag(new_tag, field="proposed platform pin") < parse_tag(
        old_tag, field="base platform pin"
    ):
        raise CompatibilityError(f"platform downgrade is prohibited: {old_tag} -> {new_tag}")
    if classify_only:
        return CheckResult(old_tag, new_tag, changed=True, verified=False)

    labels = parse_labels(labels_json)
    manifest, migration = tag_fetcher(new_tag, expected_fingerprint)
    release = release_fetcher(new_tag, github_token)
    validate_release_contract(
        old_tag,
        new_tag,
        manifest,
        migration,
        release,
        labels,
        expected_fingerprint,
    )
    return CheckResult(old_tag, new_tag, changed=True, verified=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--pull-request-number", type=int)
    parser.add_argument("--labels-json", default="[]")
    parser.add_argument("--classify-only", action="store_true")
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    arguments = parser.parse_args()
    try:
        root = arguments.root.resolve()
        if arguments.pull_request_number is not None:
            fetch_pull_request_head(
                root, arguments.pull_request_number, arguments.head_sha
            )
        result = run_check(
            root,
            arguments.base_sha,
            arguments.head_sha,
            arguments.labels_json,
            os.environ.get("PLATFORM_RELEASE_SIGNER_FINGERPRINT", ""),
            os.environ.get("GITHUB_TOKEN"),
            classify_only=arguments.classify_only,
        )
    except (CompatibilityError, OSError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    if arguments.github_output is not None:
        with arguments.github_output.open("a", encoding="utf-8") as output:
            output.write(f"platform_pin_changed={str(result.changed).lower()}\n")
    if result.changed and result.verified:
        print(f"verified compatible platform transition {result.old_tag} -> {result.new_tag}")
    elif result.changed:
        print(f"platform pin change classified: {result.old_tag} -> {result.new_tag}")
    else:
        print(
            f"platform pin unchanged at {result.new_tag}; trusted signer variable checked "
            "and network release verification skipped"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
