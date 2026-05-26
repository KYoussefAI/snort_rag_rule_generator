"""Download trusted real Snort rule sources into the local knowledge base."""
from __future__ import annotations

import json

from snort_rag.knowledge_base import DEFAULT_KB_DIR, fetch_trusted_rule_kb


def main() -> None:
    summary = fetch_trusted_rule_kb(DEFAULT_KB_DIR)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
