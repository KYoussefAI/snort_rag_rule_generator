# Dataset provenance notes

The processed dataset must now start from persisted trusted-source real Snort rules
stored in `data/knowledge_base/trusted_rule_kb.csv`.

Trusted sources used for the KB:

- Snort Community Rules
- Emerging Threats Open Rules
- Snort documentation for syntax validation and interpretation

Each generated dataset row must preserve the original real rule in the `rule` and
`base_rule` fields and record traceability with `kb_id`, `source_name`,
`source_url`, `source_archive`, `source_file`, `base_rule_sid`, and
`base_rule_msg`.

The augmentation step is limited to generating additional natural-language
descriptions for those real rules. It must not invent training labels from rules
that are not present in the trusted knowledge base.
