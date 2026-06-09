#!/usr/bin/env python
"""Create a safe academic submission archive."""
from __future__ import annotations

import argparse
from pathlib import Path
import tarfile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXCLUDES = {
    ".git",
    ".pytest_cache",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".env",
}


def _include(path: Path, include_pcaps: bool) -> bool:
    rel = path.relative_to(PROJECT_ROOT)
    if any(part in DEFAULT_EXCLUDES for part in rel.parts):
        return False
    if path.suffix in {".pyc", ".pyo"}:
        return False
    if "tests/pcaps/generated" in rel.as_posix() and not include_pcaps:
        return False
    return True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=PROJECT_ROOT / "results" / "snort_rag_submission_package.tar.gz")
    parser.add_argument("--include-synthetic-pcaps", action="store_true")
    args = parser.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(out_path, "w:gz") as archive:
        for path in PROJECT_ROOT.rglob("*"):
            if path == out_path or not _include(path, args.include_synthetic_pcaps):
                continue
            archive.add(path, arcname=Path("snort_rag_rule_generator") / path.relative_to(PROJECT_ROOT))
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
