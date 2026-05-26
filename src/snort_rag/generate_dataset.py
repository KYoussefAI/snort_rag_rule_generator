"""Legacy experimental generator for trusted-rule expansion.

This module is kept only for older experiments that expanded a trusted Snort-rule
knowledge base into large synthetic retrieval corpora. It is not part of the
official Person 1 dataset workflow. The submitted project uses
`data/processed/final_snort_dataset.csv` as the official personal dataset, and
the application, notebook, runner, and validation flow must not depend on the
`snort_generated_dataset.*` outputs produced here.
"""
from __future__ import annotations

import argparse
import csv
import itertools
import json
import random
from pathlib import Path
from typing import Dict, Iterable, Iterator, List

from snort_rag.knowledge_base import DEFAULT_KB_CSV, load_rule_kb
from snort_rag.rule_parser import option_coverage, parse_rule, validate_rule
from snort_rag.source_manifest import TRUSTED_SOURCES
from snort_rag.templates import SEVERITY

PROJECT_ROOT = Path(__file__).resolve().parents[2]
LEGACY_OUT_DIR = PROJECT_ROOT / "data" / "experiments" / "legacy_generated"
LEGACY_SUMMARY_NAME = "snort_generated_dataset_summary.json"

STYLE_PREFIXES = [
    "Formal analyst request:",
    "SOC alert description:",
    "Detection engineering note:",
    "Blue-team scenario:",
    "Security monitoring query:",
    "Incident triage request:",
]

TARGET_HINTS = [
    "internal web server",
    "DNS resolver",
    "mail gateway",
    "domain controller",
    "user workstation segment",
    "DMZ application host",
    "server VLAN",
]


def _trusted_source_map() -> Dict[str, Dict[str, str]]:
    return {source["name"]: source for source in TRUSTED_SOURCES}


def _source_manifest_fieldnames() -> List[str]:
    fieldnames = set()
    for source in TRUSTED_SOURCES:
        fieldnames.update(source.keys())
    return sorted(fieldnames)


def _decode_keywords(raw: str) -> List[str]:
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return [str(item) for item in parsed if str(item).strip()]


def _msg_without_local_tokens(msg: str) -> str:
    return msg.replace("ET ", "").replace("GPL ", "").replace("COMMUNITY ", "").strip()


def _severity_for(attack_type: str, classtype: str) -> str:
    if attack_type in SEVERITY:
        return SEVERITY[attack_type]
    lower = classtype.lower()
    if "trojan" in lower or "attempted-admin" in lower:
        return "high"
    if "web-application-attack" in lower:
        return "high"
    if "policy" in lower:
        return "medium"
    if "recon" in lower:
        return "medium"
    return "medium"


def _log_example(parsed_rule, keywords: List[str]) -> str:
    tokens = []
    if parsed_rule.protocol:
        tokens.append(f"PROTO={parsed_rule.protocol.upper()}")
    if parsed_rule.src:
        tokens.append(f"SRC={parsed_rule.src}")
    if parsed_rule.dst:
        tokens.append(f"DST={parsed_rule.dst}")
    if parsed_rule.dst_port:
        tokens.append(f"DPT={parsed_rule.dst_port}")
    if keywords:
        tokens.append("KEYWORDS=" + ",".join(keywords[:3]))
    return " ".join(tokens)


def _descriptions(rule_row: Dict[str, str], idx_seed: int, multiplier: int) -> List[str]:
    parsed = parse_rule(rule_row["rule"])
    msg = _msg_without_local_tokens(rule_row.get("msg", "") or "Snort alert")
    keywords = _decode_keywords(rule_row.get("content_keywords", ""))
    target = TARGET_HINTS[idx_seed % len(TARGET_HINTS)]
    protocol = parsed.protocol.upper()
    dst_port = parsed.dst_port
    source_file = Path(rule_row.get("source_file", "")).name
    classtype = rule_row.get("classtype", "")
    keyword_text = ", ".join(keywords[:3]) if keywords else "rule-specific payload indicators"
    variants = [
        f"{STYLE_PREFIXES[0]} Detect traffic matching the real Snort rule '{msg}' against the {target}.",
        f"{STYLE_PREFIXES[1]} Build an alert for {msg}. Protocol {protocol}, destination port {dst_port}, based on the trusted rule source {source_file}.",
        f"{STYLE_PREFIXES[2]} We need a Snort signature equivalent to the real rule '{msg}' with classtype {classtype}.",
        f"{STYLE_PREFIXES[3]} Suspicious activity resembles {msg}. Focus on payload markers such as {keyword_text}.",
        f"{STYLE_PREFIXES[4]} Use the trusted-source rule semantics for {msg}. Keep the alert aligned with {protocol} traffic to {dst_port}.",
        f"{STYLE_PREFIXES[5]} Investigate an event that should match the real rule '{msg}' from {source_file}.",
    ]
    return [variants[i % len(variants)] for i in range(multiplier)]


def iter_rows(multiplier: int = 6, seed: int = 42, kb_path: Path | str = DEFAULT_KB_CSV) -> Iterator[Dict[str, object]]:
    random.seed(seed)
    kb_rows = load_rule_kb(kb_path)
    if not kb_rows:
        raise ValueError("Trusted rule knowledge base is empty. Fetch real sources first.")
    trusted = _trusted_source_map()
    row_id = 1
    for kb_index, kb_row in enumerate(kb_rows):
        descriptions = _descriptions(kb_row, kb_index + seed, multiplier)
        valid, errors = validate_rule(kb_row["rule"])
        parsed = parse_rule(kb_row["rule"])
        keywords = _decode_keywords(kb_row.get("content_keywords", ""))
        source_meta = trusted.get(kb_row["source_name"], {})
        for local_index, description in enumerate(descriptions, 1):
            row = {
                "id": f"SNORT-RAG-{row_id:07d}",
                "kb_id": kb_row["kb_id"],
                "description_nl": description,
                "normalized_description": description.lower(),
                "label": "malicious",
                "attack_type": kb_row.get("attack_type", ""),
                "attack_family": kb_row.get("classtype", "") or kb_row.get("attack_type", ""),
                "severity": _severity_for(kb_row.get("attack_type", ""), kb_row.get("classtype", "")),
                "rule": kb_row["rule"],
                "base_rule": kb_row["rule"],
                "rule_valid_by_parser": valid,
                "rule_validation_errors": " | ".join(errors),
                "option_coverage": option_coverage(kb_row["rule"]),
                "source_name": kb_row["source_name"],
                "source_url": kb_row["source_url"],
                "source_archive": kb_row.get("archive_name", ""),
                "source_file": kb_row.get("source_file", ""),
                "source_license_note": source_meta.get("license_note", ""),
                "source_usage": "generated from a persisted trusted-source real Snort rule",
                "generation_method": "real_rule_paraphrase_expansion",
                "log_example": _log_example(parsed, keywords),
                "base_rule_sid": kb_row.get("sid", ""),
                "base_rule_rev": kb_row.get("rev", ""),
                "base_rule_msg": kb_row.get("msg", ""),
                "content_keywords": json.dumps(keywords, ensure_ascii=False),
                "augmentation_index": local_index,
            }
            yield row
            row_id += 1


def build_rows(multiplier: int = 6, seed: int = 42, kb_path: Path | str = DEFAULT_KB_CSV) -> List[Dict[str, object]]:
    return list(iter_rows(multiplier=multiplier, seed=seed, kb_path=kb_path))


def export_dataset(rows: List[Dict[str, object]], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].keys()) if rows else []
    with (out_dir / "snort_generated_dataset.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    (out_dir / "snort_generated_dataset.json").write_text(
        json.dumps(rows, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    with (out_dir / "snort_generated_dataset.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    source_manifest = TRUSTED_SOURCES
    raw_dir = PROJECT_ROOT / "data" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    with (raw_dir / "trusted_sources_manifest.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=_source_manifest_fieldnames())
        writer.writeheader()
        writer.writerows(source_manifest)

    attack_types = sorted({str(row["attack_type"]) for row in rows})
    valid_rows = [row for row in rows if row["rule_valid_by_parser"]]
    source_names = sorted({str(row["source_name"]) for row in rows})
    summary = {
        "rows": len(rows),
        "trusted_rule_rows": len({str(row["kb_id"]) for row in rows}),
        "rows_per_rule": len(rows) // max(1, len({str(row["kb_id"]) for row in rows})),
        "attack_types": attack_types,
        "valid_rule_rate": len(valid_rows) / max(1, len(rows)),
        "sources": source_names,
    }
    (out_dir / LEGACY_SUMMARY_NAME).write_text(json.dumps(summary, indent=2), encoding="utf-8")


def export_dataset_streaming(multiplier: int, seed: int, kb_path: Path | str, out_dir: Path) -> Dict[str, object]:
    out_dir.mkdir(parents=True, exist_ok=True)
    rows_iter = iter_rows(multiplier=multiplier, seed=seed, kb_path=kb_path)
    first_row = next(rows_iter, None)
    if first_row is None:
        raise ValueError("No rows generated from the trusted rule knowledge base.")

    csv_path = out_dir / "snort_generated_dataset.csv"
    json_path = out_dir / "snort_generated_dataset.json"
    jsonl_path = out_dir / "snort_generated_dataset.jsonl"
    fieldnames = list(first_row.keys())
    source_names = set()
    attack_types = set()
    kb_ids = set()
    row_count = 0
    valid_count = 0

    def update_summary(row: Dict[str, object]) -> None:
        nonlocal row_count, valid_count
        row_count += 1
        if row["rule_valid_by_parser"]:
            valid_count += 1
        source_names.add(str(row["source_name"]))
        attack_types.add(str(row["attack_type"]))
        kb_ids.add(str(row["kb_id"]))

    with csv_path.open("w", newline="", encoding="utf-8") as csv_handle, \
            json_path.open("w", encoding="utf-8") as json_handle, \
            jsonl_path.open("w", encoding="utf-8") as jsonl_handle:
        writer = csv.DictWriter(csv_handle, fieldnames=fieldnames)
        writer.writeheader()
        json_handle.write("[\n")
        for index, row in enumerate(itertools.chain([first_row], rows_iter)):
            writer.writerow(row)
            jsonl_handle.write(json.dumps(row, ensure_ascii=False) + "\n")
            json_handle.write(("  " if index == 0 else ",\n  ") + json.dumps(row, ensure_ascii=False))
            update_summary(row)
        json_handle.write("\n]\n")

    source_manifest = TRUSTED_SOURCES
    raw_dir = PROJECT_ROOT / "data" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    with (raw_dir / "trusted_sources_manifest.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=_source_manifest_fieldnames())
        writer.writeheader()
        writer.writerows(source_manifest)

    summary = {
        "rows": row_count,
        "trusted_rule_rows": len(kb_ids),
        "rows_per_rule": row_count // max(1, len(kb_ids)),
        "attack_types": sorted(attack_types),
        "valid_rule_rate": valid_count / max(1, row_count),
        "sources": sorted(source_names),
    }
    (out_dir / LEGACY_SUMMARY_NAME).write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--multiplier", type=int, default=6, help="Rows to generate per trusted base rule.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--kb", type=Path, default=DEFAULT_KB_CSV, help="Trusted rule knowledge-base CSV path.")
    parser.add_argument("--out", type=Path, default=LEGACY_OUT_DIR)
    args = parser.parse_args()
    summary = export_dataset_streaming(
        multiplier=args.multiplier,
        seed=args.seed,
        kb_path=args.kb,
        out_dir=args.out,
    )
    print(f"Generated {summary['rows']} rows in {args.out} from {args.kb}")


if __name__ == "__main__":
    main()
