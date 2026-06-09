# Snort RAG Personal Dataset Card

## Purpose

This dataset supports an academic NLP/RAG system that generates educational Snort IDS rules from natural-language descriptions of suspicious network behavior.

## Composition

- Rows: 200
- Labels: 10 attack/traffic classes, balanced at 20 rows each
- Source types: 80 manual rows and 120 controlled synthetic/manual variations
- Official corpus files:
  - `final_snort_dataset.csv`
  - `final_snort_dataset.jsonl`
  - `person1_rules.rules`

## Columns

Core columns include `id`, `description_naturelle`, `attack_type`, `attack_family`, `severity`, `protocol`, `src_port`, `dst_port`, `log_example`, `snort_rule_reference`, `false_positive_context`, `expected_explanation`, and `source_type`.

## Provenance

The official dataset is personally constructed for the coursework. It is not a Kaggle or public ready-made labeled dataset. External trusted-rule material and uploaded PDF chunks are separated from this official corpus and must not be reported as the main dataset.

## Synthetic Enrichment

Synthetic rows are controlled variations of personal seed examples. They vary natural-language descriptions, payload phrasing, ports, benign contexts, and explanation wording while preserving the label and defensive purpose. Synthetic rows require manual review before inclusion.

## Intended Use

Use this dataset for retrieval, classification, controlled RAG prompting, educational rule generation, and academic evaluation. Generated rules are not production-ready until reviewed by a security expert and validated with a real Snort runtime and representative traffic.

## Limitations

The dataset is intentionally small and balanced for academic experimentation. It does not represent the full diversity of enterprise network traffic, attacker behavior, or Snort deployment configurations.
