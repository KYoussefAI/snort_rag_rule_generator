from snort_rag.rule_parser import normalize_snort3_rule, validate_rule


def test_valid_rule():
    rule = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"LOCAL SSH"; flags:S; sid:900001; rev:1;)'
    valid, errors = validate_rule(rule)
    assert valid, errors


def test_invalid_rule():
    rule = 'this is not a rule'
    valid, errors = validate_rule(rule)
    assert not valid


def test_normalize_snort3_content_nocase_modifier():
    rule = 'alert tcp any any -> any 80 (msg:"SQL"; content:"UNION SELECT"; nocase; sid:900001; rev:1;)'

    normalized = normalize_snort3_rule(rule)

    assert 'content:"UNION SELECT",nocase;' in normalized
    assert "; nocase;" not in normalized
    valid, errors = validate_rule(normalized)
    assert valid, errors


def test_normalize_snort3_content_unsafe_bytes():
    rule = 'alert tcp any any -> any 80 (msg:"CMD"; content:"; \\"whoami\\" \\\\"; nocase; sid:900002; rev:1;)'

    normalized = normalize_snort3_rule(rule)

    assert 'content:"|3B| |22|whoami|22| |5C|",nocase;' in normalized
    valid, errors = validate_rule(normalized)
    assert valid, errors
