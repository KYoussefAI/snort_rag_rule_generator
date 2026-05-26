"""Trusted real-rule knowledge base ingestion and loading utilities."""
from __future__ import annotations

import csv
import io
import json
import re
import tarfile
import urllib.request
from pathlib import Path
from typing import Dict, Iterable, List

from snort_rag.rule_parser import extract_sid, parse_rule
from snort_rag.source_manifest import TRUSTED_SOURCES
from snort_rag.templates import detect_attack_type

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_KB_DIR = PROJECT_ROOT / "data" / "knowledge_base"
DEFAULT_KB_CSV = DEFAULT_KB_DIR / "trusted_rule_kb.csv"
DEFAULT_KB_JSONL = DEFAULT_KB_DIR / "trusted_rule_kb.jsonl"
DEFAULT_FETCH_SUMMARY = DEFAULT_KB_DIR / "fetch_summary.json"

ARCHIVE_SOURCES = [
    source for source in TRUSTED_SOURCES
    if source.get("access") == "archive"
]

RULE_LINE_RE = re.compile(r"^(alert|drop|reject|pass|log|sdrop)\s+(tcp|udp|icmp|ip)\s+.+\(.+\)\s*$", re.IGNORECASE)


def _rule_msg(rule: str) -> str:
    try:
        parsed = parse_rule(rule)
    except Exception:
        return ""
    values = parsed.options.get("msg", [])
    if not values:
        return ""
    return values[0].strip().strip('"')


def _rule_rev(rule: str) -> str:
    try:
        parsed = parse_rule(rule)
    except Exception:
        return ""
    values = parsed.options.get("rev", [])
    return values[0].strip() if values else ""


def _rule_classtype(rule: str) -> str:
    try:
        parsed = parse_rule(rule)
    except Exception:
        return ""
    values = parsed.options.get("classtype", [])
    return values[0].strip() if values else ""


def _extract_content_keywords(rule: str, limit: int = 3) -> List[str]:
    keywords: List[str] = []
    try:
        parsed = parse_rule(rule)
    except Exception:
        return keywords
    for item in parsed.options.get("content", []):
        value = item.strip().strip('"')
        if value and value not in keywords:
            keywords.append(value)
        if len(keywords) >= limit:
            break
    return keywords


def _normalize_rule_line(raw_line: str) -> str:
    line = raw_line.strip()
    if line.startswith("#"):
        line = line[1:].strip()
    return line


def _build_kb_record(source: Dict[str, str], archive_name: str, member_name: str, rule: str) -> Dict[str, str]:
    msg = _rule_msg(rule)
    attack_context = " ".join(part for part in [msg, member_name, rule] if part)
    return {
        "kb_id": f"{archive_name}:{member_name}:{extract_sid(rule) or 'nosid'}",
        "source_name": source["name"],
        "source_url": source["url"],
        "source_type": source["type"],
        "archive_name": archive_name,
        "archive_url": source["url"],
        "source_file": member_name,
        "sid": str(extract_sid(rule) or ""),
        "rev": _rule_rev(rule),
        "msg": msg,
        "classtype": _rule_classtype(rule),
        "attack_type": detect_attack_type(attack_context),
        "content_keywords": json.dumps(_extract_content_keywords(rule), ensure_ascii=False),
        "rule": rule,
    }


def fetch_trusted_rule_kb(out_dir: Path = DEFAULT_KB_DIR, timeout: int = 60) -> Dict[str, object]:
    out_dir.mkdir(parents=True, exist_ok=True)
    rows: List[Dict[str, str]] = []
    summary: Dict[str, object] = {"sources": [], "rows": 0}
    for source in ARCHIVE_SOURCES:
        archive_name = source["archive_name"]
        source_summary = {
            "name": source["name"],
            "url": source["url"],
            "archive_name": archive_name,
            "downloaded": False,
            "rule_count": 0,
        }
        data = urllib.request.urlopen(source["url"], timeout=timeout).read()
        source_summary["downloaded"] = True
        archive_path = out_dir / f"{archive_name}.tar.gz"
        archive_path.write_bytes(data)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            for member in tar.getmembers():
                if not member.name.endswith(".rules"):
                    continue
                extracted = tar.extractfile(member)
                if not extracted:
                    continue
                for raw_line in extracted.read().decode("latin1", errors="ignore").splitlines():
                    line = _normalize_rule_line(raw_line)
                    if not RULE_LINE_RE.match(line):
                        continue
                    try:
                        parse_rule(line)
                    except Exception:
                        continue
                    rows.append(_build_kb_record(source, archive_name, member.name, line))
                    source_summary["rule_count"] += 1
        summary["sources"].append(source_summary)

    summary["rows"] = len(rows)
    write_rule_kb(rows, out_dir)
    (out_dir / DEFAULT_FETCH_SUMMARY.name).write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def write_rule_kb(rows: Iterable[Dict[str, str]], out_dir: Path = DEFAULT_KB_DIR) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = list(rows)
    fieldnames = [
        "kb_id",
        "source_name",
        "source_url",
        "source_type",
        "archive_name",
        "archive_url",
        "source_file",
        "sid",
        "rev",
        "msg",
        "classtype",
        "attack_type",
        "content_keywords",
        "rule",
    ]
    with (out_dir / "trusted_rule_kb.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    with (out_dir / "trusted_rule_kb.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def load_rule_kb(path: Path | str = DEFAULT_KB_CSV) -> List[Dict[str, str]]:
    kb_path = Path(path)
    if not kb_path.exists():
        raise FileNotFoundError(
            f"Trusted rule knowledge base not found at {kb_path}. "
            "Run scripts/fetch_real_sources.py first."
        )
    with kb_path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))
