"""Deterministic Snort rule templates for defensive generation.

These templates are intentionally conservative and are used as the local generation
module in the Devoir 3 implementation because the assignment explicitly forbids
OpenAI/Mistral/Ollama API usage for the TP. The templates are filled only after
retrieval, so generation is not a black-box response.
"""
from __future__ import annotations

import hashlib
import random
from typing import Dict, List

CLASSTYPE = {
    "port_scan": "attempted-recon",
    "ssh_bruteforce": "attempted-admin",
    "ftp_bruteforce": "attempted-admin",
    "rdp_bruteforce": "attempted-admin",
    "sql_injection": "web-application-attack",
    "xss": "web-application-attack",
    "directory_traversal": "web-application-attack",
    "command_injection": "web-application-attack",
    "log4shell": "web-application-attack",
    "shellshock": "web-application-attack",
    "dns_tunneling": "policy-violation",
    "dns_axfr": "attempted-recon",
    "icmp_sweep": "attempted-recon",
    "malware_c2": "trojan-activity",
    "smb_exploit": "attempted-admin",
    "suspicious_user_agent": "web-application-attack",
    "webshell_upload": "trojan-activity",
    "benign": "not-suspicious",
}

SEVERITY = {
    "port_scan": "medium",
    "ssh_bruteforce": "high",
    "ftp_bruteforce": "medium",
    "rdp_bruteforce": "high",
    "sql_injection": "high",
    "xss": "medium",
    "directory_traversal": "high",
    "command_injection": "critical",
    "log4shell": "critical",
    "shellshock": "critical",
    "dns_tunneling": "medium",
    "dns_axfr": "medium",
    "icmp_sweep": "low",
    "malware_c2": "critical",
    "smb_exploit": "critical",
    "suspicious_user_agent": "medium",
    "webshell_upload": "high",
    "benign": "none",
}

ATTACK_KEYWORDS: Dict[str, List[str]] = {
    "port_scan": ["scan", "nmap", "ports", "reconnaissance", "syn scan", "balayage"],
    "ssh_bruteforce": ["ssh", "bruteforce", "brute force", "login attempts", "22"],
    "ftp_bruteforce": ["ftp", "bruteforce", "USER", "PASS", "21"],
    "rdp_bruteforce": ["rdp", "3389", "remote desktop", "bruteforce"],
    "sql_injection": ["sql", "injection", "or 1=1", "union select", "sqli"],
    "xss": ["xss", "script", "cross site", "javascript", "<script"],
    "directory_traversal": ["../", "traversal", "etc/passwd", "path traversal", "%2e%2e"],
    "command_injection": ["command injection", ";id", "cmd=", "whoami", "wget", "curl"],
    "log4shell": ["log4j", "jndi", "ldap", "log4shell"],
    "shellshock": ["shellshock", "() {", "cgi-bin", "bash"],
    "dns_tunneling": ["dns tunnel", "tunneling", "long domain", "exfiltration dns"],
    "dns_axfr": ["axfr", "zone transfer", "dns transfer"],
    "icmp_sweep": ["icmp", "ping sweep", "echo request", "ping scan"],
    "malware_c2": ["c2", "command and control", "beacon", "malware", "botnet"],
    "smb_exploit": ["smb", "eternalblue", "445", "ms17-010", "smb exploit"],
    "suspicious_user_agent": ["sqlmap", "nikto", "acunetix", "scanner user-agent", "user agent"],
    "webshell_upload": ["webshell", "upload php", "multipart", ".php upload"],
    "benign": ["normal", "normally", "legitimate", "backup", "health check", "authorized", "benign"],
}

DESCRIPTION_TEMPLATES = {
    "port_scan": [
        "Detect a TCP SYN port scan against an internal web server.",
        "A host sends many SYN packets to several ports on $HOME_NET.",
        "Détecter un balayage de ports TCP vers un serveur interne.",
    ],
    "ssh_bruteforce": [
        "Detect repeated SSH login attempts against port 22.",
        "An external client is brute forcing SSH authentication.",
        "Détecter une attaque brute force SSH sur un serveur Linux.",
    ],
    "ftp_bruteforce": [
        "Detect repeated FTP USER commands suggesting brute force.",
        "Multiple FTP login attempts target an internal FTP server.",
        "Détecter des tentatives répétées de connexion FTP.",
    ],
    "rdp_bruteforce": [
        "Detect many RDP connection attempts to port 3389.",
        "External host tries to brute force Remote Desktop.",
        "Détecter une attaque brute force RDP vers un serveur Windows.",
    ],
    "sql_injection": [
        "Detect SQL injection in an HTTP URI using UNION SELECT.",
        "User sends ' OR 1=1 in a web request.",
        "Détecter une injection SQL dans l'URL HTTP.",
    ],
    "xss": [
        "Detect reflected XSS using script tag in HTTP URI.",
        "HTTP request contains javascript payload in a parameter.",
        "Détecter une tentative XSS dans une requête web.",
    ],
    "directory_traversal": [
        "Detect directory traversal attempting to read /etc/passwd.",
        "A web request contains encoded ../ sequences.",
        "Détecter une traversée de répertoires dans l'URI.",
    ],
    "command_injection": [
        "Detect command injection in HTTP parameter using semicolon and whoami.",
        "A request tries to execute system command through cmd parameter.",
        "Détecter une injection de commande via une URL HTTP.",
    ],
    "log4shell": [
        "Detect Log4Shell style ${jndi:ldap://...} in HTTP headers.",
        "HTTP traffic contains a JNDI LDAP lookup payload.",
        "Détecter une tentative Log4Shell dans les entêtes HTTP.",
    ],
    "shellshock": [
        "Detect Shellshock Bash function payload in HTTP header.",
        "CGI request contains () { payload in User-Agent.",
        "Détecter Shellshock dans les entêtes HTTP.",
    ],
    "dns_tunneling": [
        "Detect DNS tunneling using unusually long DNS query names.",
        "DNS requests show long encoded subdomains indicating exfiltration.",
        "Détecter un tunnel DNS avec des domaines très longs.",
    ],
    "dns_axfr": [
        "Detect DNS AXFR zone transfer attempt.",
        "Client asks for full DNS zone transfer from internal DNS server.",
        "Détecter une tentative de transfert de zone DNS AXFR.",
    ],
    "icmp_sweep": [
        "Detect ICMP ping sweep across internal hosts.",
        "Many ICMP echo requests target the internal network.",
        "Détecter un balayage ICMP de type ping sweep.",
    ],
    "malware_c2": [
        "Detect malware command and control HTTP beacon.",
        "Infected host sends periodic HTTP beacon to external server.",
        "Détecter une activité C2 malware dans le trafic HTTP.",
    ],
    "smb_exploit": [
        "Detect suspicious SMB exploit attempt against port 445.",
        "Possible EternalBlue style SMB transaction targets internal host.",
        "Détecter une tentative d'exploitation SMB sur le port 445.",
    ],
    "suspicious_user_agent": [
        "Detect suspicious scanner User-Agent such as sqlmap or Nikto.",
        "A web scanner user-agent appears in HTTP headers.",
        "Détecter un User-Agent d'outil de scan web.",
    ],
    "webshell_upload": [
        "Detect suspicious PHP web shell upload through multipart form.",
        "HTTP file upload contains .php filename and suspicious content.",
        "Détecter un upload de webshell PHP.",
    ],
    "benign": [
        "Normal HTTP health check from monitoring server.",
        "Legitimate DNS query to public resolver.",
        "Traffic backup autorisé entre deux serveurs internes.",
    ],
}


def stable_sid(text: str, base: int = 9000000, modulo: int = 900000) -> int:
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return base + (int(digest[:10], 16) % modulo)


def detect_attack_type(text: str) -> str:
    lower = text.lower()
    icmp_priority_terms = ("icmp", "ping sweep", "echo request", "icmp sweep", "internal network sweep")
    if any(term in lower for term in icmp_priority_terms):
        return "icmp_sweep"
    scores: Dict[str, int] = {}
    for attack, keywords in ATTACK_KEYWORDS.items():
        scores[attack] = sum(1 for kw in keywords if kw.lower() in lower)
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "suspicious_user_agent"


def generate_snort_rule(attack_type: str, query: str = "", sid: int | None = None, rev: int = 1) -> str:
    sid = sid or stable_sid(f"{attack_type}:{query}")
    msg = f"LOCAL {attack_type.replace('_', ' ').upper()} detected"
    classtype = CLASSTYPE.get(attack_type, "attempted-recon")
    if attack_type == "port_scan":
        return (f'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"{msg}"; flags:S; '
                f'detection_filter:track by_src, count 20, seconds 60; classtype:{classtype}; sid:{sid}; rev:{rev};)')
    if attack_type == "ssh_bruteforce":
        return (f'alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"{msg}"; flow:to_server; flags:S; '
                f'detection_filter:track by_src, count 8, seconds 60; classtype:{classtype}; sid:{sid}; rev:{rev};)')
    if attack_type == "ftp_bruteforce":
        return (f'alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"{msg}"; flow:to_server,established; '
                f'content:"USER "; nocase; detection_filter:track by_src, count 6, seconds 60; classtype:{classtype}; sid:{sid}; rev:{rev};)')
    if attack_type == "rdp_bruteforce":
        return (f'alert tcp $EXTERNAL_NET any -> $HOME_NET 3389 (msg:"{msg}"; flags:S; '
                f'detection_filter:track by_src, count 10, seconds 120; classtype:{classtype}; sid:{sid}; rev:{rev};)')
    if attack_type == "sql_injection":
        payload = random.choice(['"union select"', '"or 1=1"', '"select%20"'])
        return (f'alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"{msg}"; flow:to_server,established; '
                f'content:{payload}; http_uri; nocase; classtype:{classtype}; sid:{sid}; rev:{rev};)')
    if attack_type == "xss":
        return (f'alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"{msg}"; flow:to_server,established; '
                f'content:"<script"; http_uri; nocase; classtype:{classtype}; sid:{sid}; rev:{rev};)')
    if attack_type == "directory_traversal":
        return (f'alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"{msg}"; flow:to_server,established; '
                f'content:"../"; http_uri; content:"/etc/passwd"; http_uri; nocase; classtype:{classtype}; sid:{sid}; rev:{rev};)')
    if attack_type == "command_injection":
        return (f'alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"{msg}"; flow:to_server,established; '
                f'content:"cmd="; http_uri; content:";"; http_uri; pcre:"/(whoami|id|wget|curl)/Ui"; classtype:{classtype}; sid:{sid}; rev:{rev};)')
    if attack_type == "log4shell":
        return (f'alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"{msg}"; flow:to_server,established; '
                f'content:"${{jndi:"; http_header; nocase; pcre:"/\\$\\{{jndi:(ldap|rmi|dns):/Hi"; classtype:{classtype}; sid:{sid}; rev:{rev};)')
    if attack_type == "shellshock":
        return (f'alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"{msg}"; flow:to_server,established; '
                f'content:"() {{"; http_header; content:"/bin/"; http_header; nocase; classtype:{classtype}; sid:{sid}; rev:{rev};)')
    if attack_type == "dns_tunneling":
        return (f'alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"{msg}"; dsize:>120; '
                f'pcre:"/^[A-Za-z0-9]{{40,}}\\./"; classtype:{classtype}; sid:{sid}; rev:{rev};)')
    if attack_type == "dns_axfr":
        return (f'alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"{msg}"; content:"|00 FC 00 01|"; '
                f'offset:12; depth:4; classtype:{classtype}; sid:{sid}; rev:{rev};)')
    if attack_type == "icmp_sweep":
        return (f'alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"{msg}"; itype:8; '
                f'detection_filter:track by_src, count 15, seconds 60; classtype:{classtype}; sid:{sid}; rev:{rev};)')
    if attack_type == "malware_c2":
        return (f'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"{msg}"; flow:to_server,established; '
                f'content:"/gate.php"; http_uri; content:"User-Agent|3A|"; http_header; nocase; classtype:{classtype}; sid:{sid}; rev:{rev};)')
    if attack_type == "smb_exploit":
        return (f'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"{msg}"; flow:to_server,established; '
                f'content:"|FF|SMB"; depth:4; content:"|25 00 00 00|"; distance:0; within:80; classtype:{classtype}; sid:{sid}; rev:{rev};)')
    if attack_type == "suspicious_user_agent":
        agent = random.choice(["sqlmap", "Nikto", "acunetix"])
        return (f'alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"{msg}"; flow:to_server,established; '
                f'content:"User-Agent|3A| {agent}"; http_header; nocase; classtype:{classtype}; sid:{sid}; rev:{rev};)')
    if attack_type == "webshell_upload":
        return (f'alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"{msg}"; flow:to_server,established; '
                f'content:"Content-Disposition|3A| form-data"; http_header; content:".php"; http_client_body; nocase; classtype:{classtype}; sid:{sid}; rev:{rev};)')
    return (f'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"{msg}"; flags:S; '
            f'classtype:{classtype}; sid:{sid}; rev:{rev};)')
