# Rapport de validation du dataset

## Schema validation
Le fichier `data/processed/final_snort_dataset.csv` contient exactement les 13 colonnes attendues, sans colonne supplémentaire. Le fichier JSONL reprend le même schéma, dans le même ordre.

## Label validation
Les 200 lignes utilisent uniquement les labels autorisés:
- `port_scan`
- `ssh_bruteforce`
- `sql_injection`
- `xss`
- `command_injection`
- `directory_traversal`
- `dns_tunneling`
- `icmp_sweep`
- `malware_c2`
- `benign_traffic`

La répartition finale est de 20 lignes par `attack_type`.

## Source_type validation
Les valeurs de `source_type` sont limitées à `manual` et `synthetic_manual_variation`. Le dataset contient 80 lignes manuelles et 120 variations contrôlées.

## Port/protocol validation
Les couples protocole/port ont été vérifiés par script:
- `ssh_bruteforce` reste sur `tcp` vers `22` ou `2222`
- `dns_tunneling` cible le port `53`
- `icmp_sweep` utilise `icmp` avec `dst_port = N/A`
- les attaques web utilisent `http`, `https` ou `tcp` sur `80`, `443` ou `8080`
- `benign_traffic` reste sur des protocoles et ports plausibles

## Snort SID uniqueness validation
Chaque ligne malveillante contient une règle Snort-like avec `sid` et `rev`. Les SID sont uniques dans le CSV et dans `data/processed/person1_rules.rules`. Le fichier `.rules` exporte exactement les SID malveillants du dataset.

## Benign traffic validation
Les lignes `benign_traffic` ont une sévérité `none` ou `low` et utilisent toutes `NO_RULE_RECOMMENDED`. Elles ne servent pas à exporter des règles.

## Manual review checklist
- descriptions naturelles variées en français et en anglais
- formats de logs variés et cohérents avec le label
- contexte de faux positifs renseigné sur chaque ligne
- explication attendue non vide sur chaque ligne
- séparation respectée entre dataset personnel et base de connaissance Snort de confiance

## Final validation result
Commande exécutée:

```bash
python3 scripts/validate_dataset.py
```

Résultat: `VALIDATION PASSED`

Formulation projet:

Dataset vérifié structurellement et cohérent pour RAG. Les règles Snort-like doivent encore être testées dans un environnement Snort réel avant usage opérationnel.

## Validation renforcée des règles Snort-like
L'ancien script contrôlait surtout la structure minimale des lignes et des règles: présence des champs requis, schéma CSV/JSONL, `sid`, `rev` et quelques contraintes simples sur les ports et protocoles.

Le validateur renforcé ajoute maintenant des vérifications Snort-like plus strictes:
- équilibre des parenthèses et des guillemets
- présence d'un opérateur de direction valide
- logique de détection moins générique
- contrôle du range `sid` local/custom et de `rev >= 1`
- contrôles de cohérence `tcp`, `udp`, `icmp`
- vérifications sur les variables Snort comme `$HOME_NET` et `$EXTERNAL_NET`
- détection des règles trop génériques de type `any any -> any any`
- garde-fous sur les options HTTP et les ports web suspects

Cette validation locale réduit le risque d'accepter du texte IA aléatoire qui ressemble vaguement à une règle mais qui n'a pas une forme Snort-like crédible.

Elle ne remplace toutefois pas une vraie validation d'exécution Snort: la syntaxe finale, les avertissements moteur et le comportement réel de détection doivent encore être confirmés avec Snort et des tests PCAP.
