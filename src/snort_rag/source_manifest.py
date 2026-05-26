"""Trusted source manifest for the Snort rule generator project.

The project does not ship a copied public ruleset as a dataset. The public sources
below are used as rule-writing references and optional seed extraction sources.
Students can run scripts/fetch_real_sources.py on a machine with Internet access
to reproduce extraction of real Snort/ET rule skeletons, then generate the final
student-owned synthetic dataset.
"""

TRUSTED_SOURCES = [
    {
        "name": "Snort 3 Rule Writing Guide - Cisco Talos",
        "url": "https://docs.snort.org/",
        "type": "official_documentation",
        "access": "reference",
        "use_in_project": "Rule syntax, required options, supported detection keywords, validation rules.",
        "license_note": "Documentation reference only; no bulk copying into the dataset.",
    },
    {
        "name": "Snort Rules and IDS Software Downloads",
        "url": "https://www.snort.org/downloads",
        "type": "official_rules_download_page",
        "access": "reference",
        "use_in_project": "Official community/registered rules source reference and optional manual validation.",
        "license_note": "Community Ruleset is referenced as a real Snort source; do not redistribute proprietary/subscriber rules.",
    },
    {
        "name": "Snort Registered vs Subscriber documentation",
        "url": "https://snort.org/documents/registered-vs-subscriber",
        "type": "official_documentation",
        "access": "reference",
        "use_in_project": "Ruleset availability and licensing context.",
        "license_note": "Used only for source justification.",
    },
    {
        "name": "Emerging Threats Open Rules",
        "url": "https://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz",
        "type": "open_ruleset_optional_extraction",
        "access": "archive",
        "archive_name": "emerging_threats_open",
        "use_in_project": "Optional extraction of rule skeletons/categories to inspire student-generated data.",
        "license_note": "ET Open is commonly distributed as open rules; keep attribution and avoid submitting copied full dataset as personal dataset.",
    },
    {
        "name": "Snort Community Rules",
        "url": "https://www.snort.org/downloads/community/community-rules.tar.gz",
        "type": "official_open_ruleset",
        "access": "archive",
        "archive_name": "snort_community",
        "use_in_project": "Trusted real-rule base knowledge for dataset generation and retrieval.",
        "license_note": "Use the public community rules only and preserve source attribution.",
    },
    {
        "name": "Emerging Threats FAQ",
        "url": "https://community.emergingthreats.net/t/frequently-asked-questions/56",
        "type": "source_documentation",
        "access": "reference",
        "use_in_project": "Explains ET Open and community-maintained ruleset context.",
        "license_note": "Reference only.",
    },
]

SOURCE_URLS = {source["name"]: source["url"] for source in TRUSTED_SOURCES}
