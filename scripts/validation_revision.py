"""Read the validation pin before checking out Base tooling."""

import re
import sys
from pathlib import Path


def main() -> int:
    try:
        revision = (
            Path(__file__).resolve().parents[1] / "config/validation-revision"
        ).read_text().strip()
    except (OSError, UnicodeError):
        revision = ""
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        print(
            "Validation revision must be a full lowercase commit SHA.",
            file=sys.stderr,
        )
        return 1
    print(revision)
    return 0


if __name__ == "__main__":
    sys.exit(main())
