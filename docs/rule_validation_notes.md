# Notes de validation des règles

Le projet conserve une pré-validation locale pour filtrer les règles manifestement incohérentes avant export: présence de `alert`, `msg`, condition de détection, `classtype`, `sid`, `rev`, unicité des SID, équilibre des parenthèses et guillemets, direction `->`, cohérence protocole/port et détection de règles trop génériques.

Cette pré-validation n'est pas l'autorité finale. L'autorité syntaxique et runtime est Snort 3, exécuté via le wrapper Docker `tools/snort3-docker`.

Règle active validée:

```text
data/processed/person1_rules_snort3.rules
```

Commande Snort 3 de référence:

```bash
./tools/snort3-docker -T \
  -c /home/snorty/snort3/etc/snort/snort.lua \
  -R data/processed/person1_rules_snort3.rules
```

Artefacts de validation actuels:
- `results/snort_runtime_validation.csv`: 183 lignes PASS, `runtime_valid=True`.
- `results/pcap_test_results.csv`: 10 scénarios PASS, 9/9 catégories malveillantes détectées, `benign_traffic` avec `alert_count=0`.

Si le wrapper Docker, l'image Snort ou la configuration Snort ne sont pas disponibles dans un autre environnement, la validation runtime ne doit pas être revendiquée. Le résultat doit être marqué honnêtement comme `SKIPPED` ou en échec.
