from __future__ import annotations

import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASET_PATH = PROJECT_ROOT / "data" / "processed" / "final_snort_dataset.csv"
JSONL_PATH = PROJECT_ROOT / "data" / "processed" / "final_snort_dataset.jsonl"
RULES_PATH = PROJECT_ROOT / "data" / "processed" / "person1_rules.rules"
SUMMARY_PATH = PROJECT_ROOT / "data" / "processed" / "dataset_summary.json"

REQUIRED_COLUMNS = [
    "id",
    "description_naturelle",
    "attack_type",
    "attack_family",
    "protocol",
    "src_port",
    "dst_port",
    "severity",
    "log_example",
    "snort_rule_reference",
    "false_positive_context",
    "source_type",
    "expected_explanation",
]

ALLOWED_ATTACK_TYPES = {
    "port_scan",
    "ssh_bruteforce",
    "sql_injection",
    "xss",
    "command_injection",
    "directory_traversal",
    "dns_tunneling",
    "icmp_sweep",
    "malware_c2",
    "benign_traffic",
}

ALLOWED_SOURCE_TYPES = {"manual", "synthetic_manual_variation"}
ALLOWED_SEVERITIES = {"none", "low", "medium", "high", "critical"}
ALLOWED_PROTOCOLS = {"tcp", "udp", "icmp", "http", "https", "dns", "mixed"}
ATTACK_FAMILY_MAP = {
    "port_scan": "reconnaissance",
    "ssh_bruteforce": "credential_access",
    "sql_injection": "web_attack",
    "xss": "web_attack",
    "command_injection": "web_attack_execution",
    "directory_traversal": "web_attack_file_access",
    "dns_tunneling": "exfiltration_command_control",
    "icmp_sweep": "reconnaissance",
    "malware_c2": "command_and_control",
    "benign_traffic": "benign",
}

SID_RE = re.compile(r"\bsid\s*:\s*(\d+)\s*;")
REV_RE = re.compile(r"\brev\s*:\s*(\d+)\s*;")
RULE_PROTOCOL_RE = re.compile(r"^\s*alert\s+([a-z]+)\s+", re.IGNORECASE)
RULE_HEADER_RE = re.compile(
    r"^\s*(?P<action>alert)\s+"
    r"(?P<protocol>[a-z]+)\s+"
    r"(?P<src_addr>\S+)\s+"
    r"(?P<src_port>\S+)\s+"
    r"(?P<direction><>|->)\s+"
    r"(?P<dst_addr>\S+)\s+"
    r"(?P<dst_port>\S+)\s*"
    r"\((?P<options>.*)\)\s*$",
    re.IGNORECASE,
)
VARIABLE_RE = re.compile(r"\$[A-Z0-9_]+")

LOCAL_SID_MIN = 9_000_000
LOCAL_SID_MAX = 9_999_999
HTTP_OPTION_TOKENS = (
    "http_uri:",
    "http_raw_uri:",
    "http_header:",
    "http_raw_header:",
    "http_method:",
    "http_cookie:",
    "http_client_body:",
    "file_data;",
)
GENERIC_DETECTION_TOKENS = ("content:", "pcre:", "flags:", "detection_filter:", "threshold:", "dsize:")
ALLOWED_RULE_VARIABLES = {"$HOME_NET", "$EXTERNAL_NET", "$HTTP_PORTS", "$DNS_SERVERS", "$SSH_PORTS"}


def load_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != REQUIRED_COLUMNS:
            raise ValueError(
                f"Invalid CSV columns. Expected {REQUIRED_COLUMNS}, got {reader.fieldnames}"
            )
        return [{key: (value or "").strip() for key, value in row.items()} for row in reader]


def _port_ok(value: str) -> bool:
    if value in {"any", "N/A"}:
        return True
    if not value.isdigit():
        return False
    return 0 <= int(value) <= 65535


def _balanced_quotes(rule: str) -> bool:
    escaped = False
    quote_count = 0
    for char in rule:
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == '"':
            quote_count += 1
    return quote_count % 2 == 0


def _balanced_parentheses(rule: str) -> bool:
    depth = 0
    in_quotes = False
    escaped = False
    for char in rule:
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == '"':
            in_quotes = not in_quotes
            continue
        if in_quotes:
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0 and not in_quotes


def _extract_rule_header(rule: str) -> dict[str, str] | None:
    match = RULE_HEADER_RE.match(rule)
    return match.groupdict() if match else None


def _has_detection_logic(rule: str) -> bool:
    return any(token in rule for token in GENERIC_DETECTION_TOKENS)


def _port_token_is_any(value: str) -> bool:
    return value.lower() == "any"


def _validate_rule_structure(rule: str, expected_protocol: str) -> list[str]:
    errors: list[str] = []
    if not rule.startswith("alert "):
        errors.append("rule must start with 'alert'")
    if not _balanced_parentheses(rule):
        errors.append("rule has unbalanced parentheses")
    if not _balanced_quotes(rule):
        errors.append("rule has unbalanced quotes")
    if "msg:" not in rule:
        errors.append("rule must contain msg")
    if "classtype:" not in rule:
        errors.append("rule must contain classtype")
    if not SID_RE.search(rule):
        errors.append("rule must contain sid")
    rev_match = REV_RE.search(rule)
    if not rev_match:
        errors.append("rule must contain rev")
    elif int(rev_match.group(1)) < 1:
        errors.append("rule rev must be >= 1")
    if not _has_detection_logic(rule):
        errors.append("rule must contain stronger detection logic, not only metadata")
    header = _extract_rule_header(rule)
    if not header:
        errors.append("rule header is invalid or direction operator is missing")
    else:
        rule_protocol = header["protocol"].lower()
        if expected_protocol in {"http", "https"} and rule_protocol != "tcp":
            errors.append("http/https dataset rows must map to tcp rule protocol")
        elif expected_protocol not in {"http", "https", "mixed"} and rule_protocol != expected_protocol:
            errors.append(
                f"rule protocol {rule_protocol} does not match dataset protocol {expected_protocol}"
            )
        if header["direction"] not in {"->", "<>"}:
            errors.append("rule must use a valid direction operator")

        referenced_variables = set(VARIABLE_RE.findall(rule))
        invalid_variables = sorted(referenced_variables - ALLOWED_RULE_VARIABLES)
        if invalid_variables:
            errors.append(f"rule uses unsupported Snort variables: {', '.join(invalid_variables)}")
        if "$HOME_NET" not in referenced_variables or "$EXTERNAL_NET" not in referenced_variables:
            errors.append("rule should reference both $HOME_NET and $EXTERNAL_NET")

        sid_match = SID_RE.search(rule)
        if sid_match:
            sid_value = int(sid_match.group(1))
            if not (LOCAL_SID_MIN <= sid_value <= LOCAL_SID_MAX):
                errors.append(
                    f"rule sid {sid_value} must stay in the local/custom range {LOCAL_SID_MIN}-{LOCAL_SID_MAX}"
                )

        uses_http_options = any(token in rule for token in HTTP_OPTION_TOKENS)
        dst_port = header["dst_port"]
        src_port = header["src_port"]
        web_ports = {"80", "443", "8080", "$HTTP_PORTS"}
        if uses_http_options and rule_protocol != "tcp":
            errors.append("HTTP sticky-buffer options require tcp rules")
        if uses_http_options and dst_port not in web_ports:
            errors.append("HTTP sticky-buffer options should target a web server port")

        if expected_protocol in {"http", "https"} and dst_port not in web_ports:
            errors.append("web dataset rows should target 80/443/8080 or $HTTP_PORTS")
        if expected_protocol in {"http", "https"} and _port_token_is_any(dst_port):
            errors.append("web dataset rows should not use any-any destination ports")

        if rule_protocol == "tcp":
            if "flow:" not in rule and not any(
                token in rule for token in ("content:", "pcre:", "flags:", "detection_filter:", "threshold:", "dsize:")
            ):
                errors.append("tcp rules should include flow or another tcp-oriented sanity check")
            if expected_protocol in {"http", "https"} and "flow:to_server,established" not in rule:
                errors.append("web tcp rules should usually use flow:to_server,established")
        elif rule_protocol == "udp":
            if any(token in rule for token in ("flags:", "flow:to_server,established")):
                errors.append("udp rules should not use tcp-only flags or established flow checks")
        elif rule_protocol == "icmp":
            if any(token in rule for token in ("flags:", "flow:")):
                errors.append("icmp rules should not use tcp-only flow or flags options")
            if src_port.lower() != "any" or dst_port.lower() != "any":
                errors.append("icmp rules should use any/any ports")

        if expected_protocol == "icmp" and rule_protocol != "icmp":
            errors.append("icmp dataset rows must map to icmp rules")
        if expected_protocol == "udp" and rule_protocol != "udp":
            errors.append("udp dataset rows must map to udp rules")

        if _port_token_is_any(src_port) and _port_token_is_any(dst_port) and not any(
            token in rule for token in ("content:", "pcre:", "flags:", "dsize:")
        ):
            errors.append("overly generic any-any rule without a strong payload or protocol discriminator")
    return errors


def _log_supports_row(row: dict[str, str]) -> bool:
    text = " ".join(
        [
            row["description_naturelle"].lower(),
            row["log_example"].lower(),
            row["expected_explanation"].lower(),
            row["snort_rule_reference"].lower(),
        ]
    )
    required_tokens = {
        "port_scan": ["syn", "scan", "dpt=", "connection attempts"],
        "ssh_bruteforce": ["ssh", "failed password", "authentication failure", "invalid user"],
        "sql_injection": ["union", "select", "or 1=1", "sql", "sleep("],
        "xss": ["script", "onerror", "xss", "<svg", "javascript:"],
        "command_injection": [";", "wget", "curl", "/bin/sh", "cmd="],
        "directory_traversal": ["../", "..%2f", "/etc/passwd", "win.ini"],
        "dns_tunneling": ["dns", "query", "txt", "long subdomain", "base64"],
        "icmp_sweep": ["icmp", "echo", "sweep", "multiple hosts"],
        "malware_c2": ["beacon", "c2", "periodic", "callback", "heartbeat"],
        "benign_traffic": ["normal", "health", "backup", "monitoring", "benign"],
    }
    return any(token in text for token in required_tokens[row["attack_type"]])


def _validate_rule_attack_semantics(rule: str, row: dict[str, str]) -> list[str]:
    errors: list[str] = []
    header = _extract_rule_header(rule)
    if not header:
        return errors

    attack_type = row["attack_type"]
    protocol = header["protocol"].lower()
    src_addr = header["src_addr"]
    dst_addr = header["dst_addr"]
    dst_port = header["dst_port"]

    if attack_type in {"port_scan", "ssh_bruteforce", "sql_injection", "xss", "command_injection", "directory_traversal", "icmp_sweep"}:
        if src_addr != "$EXTERNAL_NET" or dst_addr != "$HOME_NET":
            errors.append("rule direction should be $EXTERNAL_NET -> $HOME_NET for inbound attack traffic")
    if attack_type in {"dns_tunneling", "malware_c2"}:
        if src_addr != "$HOME_NET" or dst_addr != "$EXTERNAL_NET":
            errors.append("rule direction should be $HOME_NET -> $EXTERNAL_NET for outbound traffic")

    if attack_type == "ssh_bruteforce":
        if protocol != "tcp" or dst_port not in {"22", "2222", "$SSH_PORTS"}:
            errors.append("ssh brute-force rules should be tcp and target 22/2222/$SSH_PORTS")
    if attack_type == "dns_tunneling":
        if protocol not in {"dns", "udp", "tcp"} or dst_port not in {"53", "$DNS_SERVERS"}:
            errors.append("dns tunneling rules should target port 53 or $DNS_SERVERS")
    if attack_type == "icmp_sweep":
        if protocol != "icmp":
            errors.append("icmp sweep rules should use the icmp protocol")
    if attack_type in {"sql_injection", "xss", "command_injection", "directory_traversal"}:
        if dst_port not in {"80", "443", "8080", "$HTTP_PORTS"}:
            errors.append("web attack rules should stay on web service ports")
    if attack_type == "malware_c2" and dst_port not in {"53", "80", "443", "8080", "8443"}:
        errors.append("malware C2 rules should stay on expected egress ports")

    return errors


def validate_rows(rows: list[dict[str, str]], rules_lines: list[str]) -> tuple[list[str], dict[str, object]]:
    errors: list[str] = []
    ids = [row["id"] for row in rows]
    if len(ids) != len(set(ids)):
        errors.append("Dataset IDs are not unique.")

    sids: list[str] = []
    manual_rows = 0
    source_type_counts = Counter()
    attack_counts = Counter()
    family_counts = Counter()
    severity_counts = Counter()
    protocol_counts = Counter()

    for idx, row in enumerate(rows, 2):
        attack_type = row["attack_type"]
        protocol = row["protocol"]
        source_type = row["source_type"]
        severity = row["severity"]
        attack_counts[attack_type] += 1
        family_counts[row["attack_family"]] += 1
        severity_counts[severity] += 1
        protocol_counts[protocol] += 1
        source_type_counts[source_type] += 1
        if source_type == "manual":
            manual_rows += 1

        for key in REQUIRED_COLUMNS:
            if not row[key]:
                errors.append(f"Row {idx} has empty field: {key}")

        if attack_type not in ALLOWED_ATTACK_TYPES:
            errors.append(f"Row {idx} has invalid attack_type: {attack_type}")
        if row["attack_family"] != ATTACK_FAMILY_MAP.get(attack_type, ""):
            errors.append(f"Row {idx} has inconsistent attack_family for {attack_type}")
        if source_type not in ALLOWED_SOURCE_TYPES:
            errors.append(f"Row {idx} has invalid source_type: {source_type}")
        if severity not in ALLOWED_SEVERITIES:
            errors.append(f"Row {idx} has invalid severity: {severity}")
        if protocol not in ALLOWED_PROTOCOLS:
            errors.append(f"Row {idx} has invalid protocol: {protocol}")
        if not _port_ok(row["src_port"]):
            errors.append(f"Row {idx} has invalid src_port: {row['src_port']}")
        if not _port_ok(row["dst_port"]):
            errors.append(f"Row {idx} has invalid dst_port: {row['dst_port']}")

        if attack_type == "benign_traffic":
            if severity not in {"none", "low"}:
                errors.append(f"Row {idx} benign_traffic severity must be none or low")
            if row["snort_rule_reference"] != "NO_RULE_RECOMMENDED":
                errors.append(f"Row {idx} benign_traffic must use NO_RULE_RECOMMENDED")
        else:
            if row["snort_rule_reference"] == "NO_RULE_RECOMMENDED":
                errors.append(f"Row {idx} malicious row cannot use NO_RULE_RECOMMENDED")
            else:
                rule_errors = _validate_rule_structure(row["snort_rule_reference"], protocol)
                errors.extend([f"Row {idx} {error}" for error in rule_errors])
                semantic_errors = _validate_rule_attack_semantics(row["snort_rule_reference"], row)
                errors.extend([f"Row {idx} {error}" for error in semantic_errors])
                match = SID_RE.search(row["snort_rule_reference"])
                if match:
                    sids.append(match.group(1))

        if attack_type == "ssh_bruteforce" and not (protocol == "tcp" and row["dst_port"] in {"22", "2222"}):
            errors.append(f"Row {idx} ssh_bruteforce must use tcp to 22 or 2222")
        if attack_type == "dns_tunneling" and not (protocol in {"dns", "udp", "tcp"} and row["dst_port"] == "53"):
            errors.append(f"Row {idx} dns_tunneling must target port 53 with dns/udp/tcp")
        if attack_type == "icmp_sweep" and not (protocol == "icmp" and row["dst_port"] in {"N/A", "any"}):
            errors.append(f"Row {idx} icmp_sweep must use icmp and dst_port N/A or any")
        if attack_type in {"sql_injection", "xss", "command_injection", "directory_traversal"}:
            if protocol not in {"http", "https", "tcp"} or row["dst_port"] not in {"80", "443", "8080"}:
                errors.append(f"Row {idx} web attack must use http/https/tcp with port 80/443/8080")
        if attack_type == "port_scan" and protocol not in {"tcp", "mixed"}:
            errors.append(f"Row {idx} port_scan must use tcp or mixed")
        if attack_type == "malware_c2" and row["dst_port"] not in {"80", "443", "8080", "53", "8443"}:
            errors.append(f"Row {idx} malware_c2 must use expected destination ports")

        if not _log_supports_row(row):
            errors.append(f"Row {idx} log_example/explanation do not support the assigned label strongly enough")

    if len(sids) != len(set(sids)):
        errors.append("Snort SID values are not unique in dataset rows.")

    exported_sids: list[str] = []
    for line_no, line in enumerate(rules_lines, 1):
        if not line.strip():
            continue
        if "NO_RULE_RECOMMENDED" in line:
            errors.append(f"Rule export line {line_no} contains benign placeholder")
            continue
        protocol_match = RULE_PROTOCOL_RE.match(line)
        expected_protocol = protocol_match.group(1).lower() if protocol_match else "tcp"
        export_rule_errors = _validate_rule_structure(line, expected_protocol)
        errors.extend([f"Rule export line {line_no} {error}" for error in export_rule_errors])
        sid_match = SID_RE.search(line)
        if not sid_match:
            errors.append(f"Rule export line {line_no} is missing sid")
        else:
            exported_sids.append(sid_match.group(1))
        if not REV_RE.search(line):
            errors.append(f"Rule export line {line_no} is missing rev")
    if len(exported_sids) != len(set(exported_sids)):
        errors.append("Snort SID values are not unique in exported rules.")
    if set(exported_sids) != set(sids):
        errors.append("Exported rules SIDs do not exactly match malicious dataset SIDs.")

    metrics = {
        "total_rows": len(rows),
        "manual_rows": manual_rows,
        "synthetic_manual_variation_rows": source_type_counts["synthetic_manual_variation"],
        "rows_per_attack_type": dict(sorted(attack_counts.items())),
        "rows_per_attack_family": dict(sorted(family_counts.items())),
        "severity_distribution": dict(sorted(severity_counts.items())),
        "protocol_distribution": dict(sorted(protocol_counts.items())),
        "source_type_distribution": dict(sorted(source_type_counts.items())),
        "rules_exported_count": len(rules_lines),
    }
    return errors, metrics


def validate_jsonl(rows: list[dict[str, str]]) -> list[str]:
    errors: list[str] = []
    with JSONL_PATH.open(encoding="utf-8") as handle:
        jsonl_rows = [json.loads(line) for line in handle if line.strip()]
    if len(jsonl_rows) != len(rows):
        errors.append("JSONL row count does not match CSV row count.")
    for idx, row in enumerate(jsonl_rows, 1):
        if list(row.keys()) != REQUIRED_COLUMNS:
            errors.append(f"JSONL row {idx} columns do not match the required schema.")
            break
    return errors


def main() -> int:
    for path in [DATASET_PATH, JSONL_PATH, RULES_PATH, SUMMARY_PATH]:
        if not path.exists():
            print(f"Missing required file: {path}")
            return 1

    try:
        rows = load_csv_rows(DATASET_PATH)
    except Exception as exc:
        print(f"CSV validation failed: {exc}")
        return 1

    rules_lines = [line.strip() for line in RULES_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
    errors, metrics = validate_rows(rows, rules_lines)
    errors.extend(validate_jsonl(rows))

    try:
        summary = json.loads(SUMMARY_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        errors.append(f"dataset_summary.json is invalid JSON: {exc}")
        summary = {}

    if summary:
        if summary.get("total_rows") != metrics["total_rows"]:
            errors.append("dataset_summary.json total_rows does not match the dataset.")
        if summary.get("rules_exported_count") != metrics["rules_exported_count"]:
            errors.append("dataset_summary.json rules_exported_count does not match exported rules.")

    if errors:
        print("VALIDATION FAILED")
        for error in errors:
            print(f"- {error}")
        return 1

    print("VALIDATION PASSED")
    print(json.dumps(metrics, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
