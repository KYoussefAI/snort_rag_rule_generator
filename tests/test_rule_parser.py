from snort_rag.rule_parser import validate_rule


def test_valid_rule():
    rule = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"LOCAL SSH"; flags:S; sid:900001; rev:1;)'
    valid, errors = validate_rule(rule)
    assert valid, errors


def test_invalid_rule():
    rule = 'this is not a rule'
    valid, errors = validate_rule(rule)
    assert not valid
