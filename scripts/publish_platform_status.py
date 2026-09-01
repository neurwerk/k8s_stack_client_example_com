#!/usr/bin/env python3
"""Publish the dedicated App's fail-closed platform compatibility status."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Callable
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

STATUS_CONTEXT = "Platform Compatibility"
SHA_PATTERN = re.compile(r"^[0-9a-f]{40,64}$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
RUN_ID_PATTERN = re.compile(r"^[1-9][0-9]*$")
DESCRIPTIONS = {
    "pending": "Trusted platform compatibility evaluation is running.",
    "success": "Platform transition is compatible and authorized.",
    "failure": "Platform compatibility failed or its approval became stale.",
    "error": "Platform compatibility infrastructure failed.",
}
API_VERSION = "2026-03-10"


class StatusError(RuntimeError):
    """A trusted status could not be published safely."""


def _request(
    request: Request,
    opener: Callable[..., Any],
) -> Any:
    try:
        with opener(request, timeout=20) as response:
            return json.load(response)
    except HTTPError as error:
        raise StatusError(f"GitHub status API failed with HTTP {error.code}") from error
    except (URLError, TimeoutError, json.JSONDecodeError) as error:
        raise StatusError(f"GitHub status API request failed: {error}") from error


def publish_status(
    *,
    repository: str,
    sha: str,
    state: str,
    run_id: str,
    run_attempt: str,
    token: str,
    server_url: str = "https://github.com",
    api_url: str = "https://api.github.com",
    opener: Callable[..., Any] = urlopen,
) -> bool:
    """Publish the App-owned status for one immutable test-merge commit."""
    if REPOSITORY_PATTERN.fullmatch(repository) is None:
        raise StatusError("GITHUB_REPOSITORY is invalid")
    if SHA_PATTERN.fullmatch(sha) is None:
        raise StatusError("status SHA must be a full hexadecimal Git object ID")
    if state not in DESCRIPTIONS:
        raise StatusError("status state is invalid")
    if RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise StatusError("workflow run ID is invalid")
    if RUN_ID_PATTERN.fullmatch(run_attempt) is None:
        raise StatusError("workflow run attempt is invalid")
    if not token:
        raise StatusError("status-only GitHub App token is missing")
    if server_url != "https://github.com" or api_url != "https://api.github.com":
        raise StatusError("GitHub status endpoints must use github.com")

    owner, name = repository.split("/", 1)
    base = f"{api_url}/repos/{quote(owner)}/{quote(name)}"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": API_VERSION,
        "User-Agent": "neurwerk-platform-status",
    }
    run_url_prefix = f"{server_url}/{repository}/actions/runs/"
    target_url = f"{run_url_prefix}{run_id}/attempts/{run_attempt}"
    body = json.dumps(
        {
            "context": STATUS_CONTEXT,
            "description": DESCRIPTIONS[state],
            "state": state,
            "target_url": target_url,
        }
    ).encode("utf-8")
    _request(
        Request(
            f"{base}/statuses/{sha}",
            data=body,
            headers={**headers, "Content-Type": "application/json"},
            method="POST",
        ),
        opener,
    )
    print(f"Published {STATUS_CONTEXT}={state} for {sha}.")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--state", required=True, choices=sorted(DESCRIPTIONS))
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    arguments = parser.parse_args()
    try:
        publish_status(
            repository=os.environ.get("GITHUB_REPOSITORY", ""),
            sha=arguments.sha,
            state=arguments.state,
            run_id=arguments.run_id,
            run_attempt=arguments.run_attempt,
            token=os.environ.get("PLATFORM_STATUS_TOKEN", ""),
            server_url=os.environ.get("GITHUB_SERVER_URL", "https://github.com"),
            api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
        )
    except StatusError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
