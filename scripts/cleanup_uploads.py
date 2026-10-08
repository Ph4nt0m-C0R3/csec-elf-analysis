"""Remove abandoned upload files older than a configurable age."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from revlearn import create_app


def cleanup(directory: Path, older_than_seconds: int) -> int:
    cutoff = time.time() - older_than_seconds
    removed = 0
    if not directory.exists():
        return removed
    for candidate in directory.glob("*.upload"):
        try:
            if candidate.is_file() and candidate.stat().st_mtime < cutoff:
                candidate.unlink()
                removed += 1
        except FileNotFoundError:
            continue
    return removed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--older-than-minutes",
        type=int,
        default=30,
        help="Delete temporary uploads older than this age (default: 30).",
    )
    args = parser.parse_args()
    app = create_app()
    count = cleanup(
        Path(app.config["UPLOAD_DIR"]),
        max(1, args.older_than_minutes) * 60,
    )
    print(f"Removed {count} abandoned upload file(s).")


if __name__ == "__main__":
    main()
