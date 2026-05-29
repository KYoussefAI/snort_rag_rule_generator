"""Small Snort rule parser/validator used by the dataset generator and evaluation.

It validates a practical subset of Snort 2/3-compatible rule syntax. The goal is
not to replace Snort's own -T validation, but to catch fake outputs before they
enter the RAG dataset or the final generated response.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Dict, List, Tuple

RULE_RE = re.compile(
    r"^(?P<action>alert|log|pass|drop|reject|sdrop)\s+"
    r"(?P<protocol>tcp|udp|icmp|ip)\s+"
    r"(?P<src>\S+)\s+(?P<src_port>\S+)\s+"
    r"(?P<direction>->|<>|<-|→)\s+"
    r"(?P<dst>\S+)\s+(?P<dst_port>\S+)\s+"
    r"\((?P<options>.*)\)\s*$",
    re.IGNORECASE,
)

REQUIRED_OPTIONS = {"msg", "sid", "rev"}
RECOMMENDED_OPTIONS = {"classtype"}
COMMON_REQUIRED_OPTIONS = ("msg", "sid", "rev", "classtype")
ATTACK_TYPE_RECOMMENDATIONS = {
    "ssh_bruteforce": (("flow",), ("detection_filter", "threshold"), ("flags", "content")),
    "sql_injection": (("flow",), ("content", "pcre"), ("nocase",)),
    "xss": (("flow",), ("content", "pcre"), ("nocase",)),
    "command_injection": (("flow",), ("content", "pcre"), ("nocase",)),
    "directory_traversal": (("flow",), ("content", "pcre"), ("nocase",)),
    "port_scan": (("flags",), ("detection_filter", "threshold")),
    "dns_tunneling": (("content", "dsize"),),
    "icmp_sweep": (("dsize", "detection_filter"),),
    "malware_c2": (("flow",), ("content",), ("detection_filter", "threshold")),
}


@dataclass
class ParsedRule:
    action: str
    protocol: str
    src: str
    src_port: str
    direction: str
    dst: str
    dst_port: str
    options: Dict[str, List[str]]
    raw_options: List[str]


def split_options(options: str) -> List[str]:
    """Split Snort options by semicolon while respecting quoted strings."""
    chunks: List[str] = []
    buf: List[str] = []
    in_quotes = False
    escaped = False
    for char in options:
        if char == '"' and not escaped:
            in_quotes = not in_quotes
        if char == ";" and not in_quotes:
            item = "".join(buf).strip()
            if item:
                chunks.append(item)
            buf = []
        else:
            buf.append(char)
        escaped = (char == "\\" and not escaped)
    tail = "".join(buf).strip()
    if tail:
        chunks.append(tail)
    return chunks


def parse_options(options: str) -> Tuple[Dict[str, List[str]], List[str]]:
    parsed: Dict[str, List[str]] = {}
    raw = split_options(options)
    for item in raw:
        if ":" in item:
            key, value = item.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
        else:
            key, value = item.strip().lower(), "true"
        parsed.setdefault(key, []).append(value)
    return parsed, raw


def parse_rule(rule: str) -> ParsedRule:
    rule = rule.strip().replace("→", "->")
    match = RULE_RE.match(rule)
    if not match:
        raise ValueError("Rule header does not match Snort syntax.")
    options, raw_options = parse_options(match.group("options"))
    return ParsedRule(
        action=match.group("action").lower(),
        protocol=match.group("protocol").lower(),
        src=match.group("src"),
        src_port=match.group("src_port"),
        direction=match.group("direction"),
        dst=match.group("dst"),
        dst_port=match.group("dst_port"),
        options=options,
        raw_options=raw_options,
    )


def extract_snort_options(rule: str) -> Dict[str, List[str]]:
    """Return parsed Snort options keyed by option name."""
    if rule == "NO_RULE_RECOMMENDED":
        return {}
    parsed = parse_rule(rule)
    return parsed.options


def detected_option_names(rule: str) -> List[str]:
    """Return normalized option names detected in a Snort-like rule."""
    if rule == "NO_RULE_RECOMMENDED":
        return []
    try:
        return sorted(extract_snort_options(rule))
    except ValueError:
        return []


def missing_required_options(rule: str, attack_type: str = "") -> List[str]:
    """Return missing common and attack-specific options for a generated rule."""
    if rule == "NO_RULE_RECOMMENDED":
        return []
    detected = set(detected_option_names(rule))
    if not detected:
        return list(COMMON_REQUIRED_OPTIONS)

    missing: List[str] = [name for name in COMMON_REQUIRED_OPTIONS if name not in detected]
    for option_group in ATTACK_TYPE_RECOMMENDATIONS.get(attack_type, ()):
        if not any(option in detected for option in option_group):
            missing.extend(option_group)
    # Preserve order while removing duplicates.
    ordered: List[str] = []
    seen = set()
    for item in missing:
        if item not in seen:
            ordered.append(item)
            seen.add(item)
    return ordered


def validate_rule(rule: str) -> Tuple[bool, List[str]]:
    errors: List[str] = []
    try:
        parsed = parse_rule(rule)
    except ValueError as exc:
        return False, [str(exc)]

    missing = sorted(REQUIRED_OPTIONS - set(parsed.options))
    if missing:
        errors.append("Missing required options: " + ", ".join(missing))
    sid_values = parsed.options.get("sid", [])
    for sid in sid_values:
        if not re.match(r"^\d+$", sid.strip()):
            errors.append("sid must be numeric")
    rev_values = parsed.options.get("rev", [])
    for rev in rev_values:
        if not re.match(r"^\d+$", rev.strip()):
            errors.append("rev must be numeric")
    msg_values = parsed.options.get("msg", [])
    for msg in msg_values:
        if not (msg.startswith('"') and msg.endswith('"')):
            errors.append("msg should be quoted")
    if "content" not in parsed.options and parsed.protocol in {"tcp", "udp"}:
        # A TCP/UDP rule can be valid without content, but for generated rules this is risky.
        if "detection_filter" not in parsed.options and "flags" not in parsed.options:
            errors.append("Generated TCP/UDP rule has no content, flags or detection_filter")
    return len(errors) == 0, errors


def option_coverage(rule: str) -> float:
    """Return a simple quality score based on useful rule options."""
    try:
        parsed = parse_rule(rule)
    except ValueError:
        return 0.0
    useful = [
        "msg", "flow", "content", "http_uri", "http_header", "pcre", "flags",
        "detection_filter", "classtype", "sid", "rev", "metadata", "reference",
        "nocase", "fast_pattern", "itype", "icode", "dsize", "byte_test",
    ]
    present = sum(1 for key in useful if key in parsed.options)
    return min(1.0, present / 9.0)


def extract_sid(rule: str) -> int | None:
    try:
        parsed = parse_rule(rule)
        sid = parsed.options.get("sid", [None])[0]
        return int(sid) if sid is not None and sid.isdigit() else None
    except Exception:
        return None
