# Notes de validation des règles

Les règles de `data/processed/person1_rules.rules` sont des références Snort-like éducatives. Elles ont été écrites pour soutenir l'explication et la récupération RAG, pas pour être considérées comme des signatures de production sans test supplémentaire.

Le script `scripts/validate_dataset.py` vérifie leur structure minimale:
- présence de `alert`
- présence de `msg`
- présence d'au moins une condition de détection
- présence de `classtype`
- présence de `sid`
- présence de `rev`
- unicité des SID

Le contrôle local a maintenant été renforcé avec des garde-fous Snort-like supplémentaires: équilibre parenthèses/guillemets, direction `->`, cohérence de protocole, contraintes sur le range local des SID, `rev >= 1`, détection de règles trop génériques et quelques vérifications ciblées `tcp`/`udp`/`icmp` et HTTP.

Différence importante:
- la pré-validation locale sert à filtrer les règles manifestement incohérentes avant export
- la validation réelle Snort est le test d'autorité final sur la syntaxe et les avertissements moteur
- des tests PCAP sont nécessaires pour vérifier le comportement de détection, la qualité des alertes et le niveau de faux positifs

Snort reste donc l'autorité finale, pas le script local.

Commande Snort à utiliser si Snort est installé:

```bash
snort -c /usr/local/etc/snort/snort.lua -R data/processed/person1_rules.rules --warn-all --pedantic
```

Limitation actuelle: `snort` n'est pas installé dans cet environnement de travail, donc seule une validation structurelle locale a été exécutée.
