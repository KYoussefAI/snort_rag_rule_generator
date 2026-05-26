import csv

from snort_rag.generate_dataset import build_rows


def test_build_rows_uses_real_rule_as_target(tmp_path):
    kb_path = tmp_path / "trusted_rule_kb.csv"
    rule = (
        'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 '
        '(msg:"ET WEB_SERVER SQL Injection attempt"; flow:to_server,established; '
        'content:"union select"; http_uri; classtype:web-application-attack; sid:2011111; rev:3;)'
    )
    with kb_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
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
            ],
        )
        writer.writeheader()
        writer.writerow({
            "kb_id": "et:test.rules:2011111",
            "source_name": "Emerging Threats Open Rules",
            "source_url": "https://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz",
            "source_type": "open_ruleset_optional_extraction",
            "archive_name": "emerging_threats_open",
            "archive_url": "https://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz",
            "source_file": "emerging-web_server.rules",
            "sid": "2011111",
            "rev": "3",
            "msg": "ET WEB_SERVER SQL Injection attempt",
            "classtype": "web-application-attack",
            "attack_type": "sql_injection",
            "content_keywords": '["union select"]',
            "rule": rule,
        })

    rows = build_rows(multiplier=3, seed=7, kb_path=kb_path)

    assert len(rows) == 3
    assert all(row["rule"] == rule for row in rows)
    assert all(row["base_rule"] == rule for row in rows)
    assert all(row["generation_method"] == "real_rule_paraphrase_expansion" for row in rows)
    assert all(row["source_usage"] == "generated from a persisted trusted-source real Snort rule" for row in rows)
    assert {row["augmentation_index"] for row in rows} == {1, 2, 3}
