"""Heuristics for estimating false-positive risk of generated Snort rules."""
from __future__ import annotations

from typing import List, Sequence

from snort_rag.rule_parser import parse_rule

NO_DETECTION_LOGIC = ("content", "pcre", "flags", "detection_filter", "threshold", "dsize")
WEB_ATTACKS = {
    "sql_injection",
    "xss",
    "directory_traversal",
    "command_injection",
    "log4shell",
    "shellshock",
    "suspicious_user_agent",
    "webshell_upload",
}
KNOWN_PORTS = {
    "ssh_bruteforce": {"22", "2222"},
    "ftp_bruteforce": {"21"},
    "rdp_bruteforce": {"3389"},
    "dns_tunneling": {"53"},
    "dns_axfr": {"53"},
    "malware_c2": {"80", "443", "$HTTP_PORTS"},
    "smb_exploit": {"445"},
}


def risk_level(score: float) -> str:
    if score <= 0.0:
        return "none"
    if score <= 0.20:
        return "low"
    if score <= 0.50:
        return "medium"
    return "high"


def detect_overly_broad_rule(rule: str) -> List[str]:
    if rule == "NO_RULE_RECOMMENDED":
        return []

    factors: List[str] = []
    try:
        parsed = parse_rule(rule)
    except ValueError:
        return ["rule header does not match Snort syntax"]

    detected = set(parsed.options)
    if parsed.src == "any" and parsed.src_port == "any" and parsed.dst == "any" and parsed.dst_port == "any":
        factors.append("rule uses any any -> any any")
    if not any(token in detected for token in NO_DETECTION_LOGIC):
        factors.append("rule has only metadata and no concrete detection logic")
    if "content" not in detected and "pcre" not in detected and parsed.protocol in {"tcp", "udp"}:
        factors.append("rule is missing content or pcre matching logic")
    return factors


def suggest_rule_improvements(rule: str, attack_type: str = "") -> List[str]:
    if rule == "NO_RULE_RECOMMENDED":
        return []

    suggestions: List[str] = []
    try:
        parsed = parse_rule(rule)
    except ValueError:
        return ["fix the Snort header and option syntax before using this rule"]

    detected = set(parsed.options)
    if "content" not in detected and "pcre" not in detected:
        suggestions.append("add a content or pcre match tied to the malicious payload")
    if parsed.protocol == "tcp" and attack_type in WEB_ATTACKS and "flow" not in detected:
        suggestions.append("add flow:to_server,established to narrow web traffic matching")
    if attack_type in KNOWN_PORTS and parsed.dst_port not in KNOWN_PORTS[attack_type] and parsed.dst_port == "any":
        suggestions.append("restrict the destination port to the service typically targeted by this attack")
    if attack_type == "ssh_bruteforce" and not any(key in detected for key in {"detection_filter", "threshold"}):
        suggestions.append("add detection_filter or threshold to model repeated SSH attempts")
    if attack_type == "port_scan":
        if "flags" not in detected:
            suggestions.append("add flags:S to focus the rule on SYN scan behavior")
        if "detection_filter" not in detected:
            suggestions.append("add detection_filter to require repeated scan activity")
    if attack_type == "dns_tunneling" and not any(key in detected for key in {"dsize", "content"}):
        suggestions.append("add dsize or a DNS query content discriminator to reduce benign DNS matches")
    if attack_type == "malware_c2":
        if parsed.direction != "->" or parsed.src != "$HOME_NET":
            suggestions.append("use outbound direction from $HOME_NET to $EXTERNAL_NET for beacon-style C2 traffic")
        if not any(key in detected for key in {"detection_filter", "threshold"}):
            suggestions.append("add repeated-beacon logic such as detection_filter or threshold")
    if not any(key in detected for key in NO_DETECTION_LOGIC):
        suggestions.append("add real detection logic instead of metadata-only options")
    return suggestions


def score_false_positive_risk(rule: str, attack_type: str = "") -> float:
    if rule == "NO_RULE_RECOMMENDED":
        return 0.0

    score = 0.0
    try:
        parsed = parse_rule(rule)
    except ValueError:
        return 1.0

    detected = set(parsed.options)
    if parsed.src == "any" and parsed.src_port == "any" and parsed.dst == "any" and parsed.dst_port == "any":
        score += 0.35
    if not any(key in detected for key in NO_DETECTION_LOGIC):
        score += 0.35
    if "content" not in detected and "pcre" not in detected and "flags" not in detected and "detection_filter" not in detected:
        score += 0.20
    if parsed.protocol == "tcp" and attack_type in WEB_ATTACKS and "flow" not in detected:
        score += 0.12
    if attack_type in KNOWN_PORTS and parsed.dst_port == "any":
        score += 0.12
    if attack_type in WEB_ATTACKS and "content" not in detected and "pcre" not in detected:
        score += 0.18
    if attack_type == "ssh_bruteforce" and not any(key in detected for key in {"detection_filter", "threshold"}):
        score += 0.18
    if attack_type == "port_scan" and "flags" not in detected:
        score += 0.12
    if attack_type == "port_scan" and "detection_filter" not in detected:
        score += 0.12
    if attack_type == "dns_tunneling" and not any(key in detected for key in {"dsize", "content"}):
        score += 0.18
    if attack_type == "malware_c2" and (parsed.direction != "->" or parsed.src != "$HOME_NET"):
        score += 0.16
    if attack_type == "malware_c2" and not any(key in detected for key in {"detection_filter", "threshold"}):
        score += 0.16
    return min(1.0, round(score, 2))


def analyze_false_positive_risk(
    rule: str,
    query: str = "",
    attack_type: str = "",
    retrieved_docs: list | None = None,
) -> dict:
    if rule == "NO_RULE_RECOMMENDED":
        return {
            "false_positive_score": 0.0,
            "false_positive_risk": "none",
            "risk_factors": [],
            "improvement_suggestions": [],
        }

    factors = detect_overly_broad_rule(rule)
    suggestions = suggest_rule_improvements(rule, attack_type=attack_type)
    score = score_false_positive_risk(rule, attack_type=attack_type)

    docs: Sequence[object] = retrieved_docs or []
    if docs and attack_type and not any(getattr(doc, "attack_type", "") == attack_type for doc in docs[:3]):
        factors.append("retrieved context does not strongly match the chosen attack type")
        if "review retrieved examples or refine the query before exporting the rule" not in suggestions:
            suggestions.append("review retrieved examples or refine the query before exporting the rule")
        score = min(1.0, round(score + 0.10, 2))
    if query and attack_type == "suspicious_user_agent" and "user" not in query.lower() and "agent" not in query.lower():
        factors.append("query does not explicitly mention a user-agent indicator")
        if "add a user-agent specific content match to keep the rule narrow" not in suggestions:
            suggestions.append("add a user-agent specific content match to keep the rule narrow")
        score = min(1.0, round(score + 0.08, 2))

    return {
        "false_positive_score": score,
        "false_positive_risk": risk_level(score),
        "risk_factors": factors,
        "improvement_suggestions": suggestions,
    }
