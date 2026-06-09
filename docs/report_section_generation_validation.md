# Génération, validation et contrôle des faux positifs

## 1. Objectif du module
L'objectif de ce module est de produire une règle Snort-like cohérente à partir d'une description textuelle d'attaque réseau, tout en gardant un contrôle local sur la qualité syntaxique, l'explication de la règle et le risque de faux positifs. Le module doit aussi pouvoir recommander explicitement l'absence de règle quand la requête décrit un trafic bénin.

## 2. Entrées
Le module s'appuie sur plusieurs types d'entrées clairement séparés:
- la requête utilisateur en langage naturel
- les documents Top-k récupérés par le pipeline RAG
- une règle Snort de référence présente dans les documents récupérés quand elle existe
- `data/processed/final_snort_dataset.csv`, qui est le dataset personnel utilisé pour la récupération RAG
- `data/knowledge_base/trusted_rule_kb.csv`, qui est une base optionnelle de références Snort externes et ne remplace pas le dataset personnel
- `data/logs/sample_network_logs.csv`, qui contient des logs synthétiques académiques utilisés pour la construction et l'évaluation contrôlée
- `data/logs/real_lab_logs/`, qui contient de petits logs de laboratoire contrôlé produits par rejeu PCAP local, parsing de paquets et sortie Snort, sans les présenter comme des logs de production d'entreprise

## 3. Architecture
Le flux suivi par le module est le suivant:

description utilisateur  
→ documents Top-k récupérés  
→ prompt enrichi contrôlé  
→ génération LLM dans le contexte RAG ou fallback déterministe explicite  
→ validation syntaxique et réparation éventuelle  
→ validation Snort 3 réelle quand les règles sont exportées
→ rejeu PCAP de laboratoire et intégration de logs de laboratoire
→ explication  
→ analyse des faux positifs

En pratique, le chemin final utilise `llm_generator.py`: le prompt contient la requête, les documents récupérés, un schéma JSON strict et les contraintes Snort. La sortie LLM est parsée, validée, réparée si nécessaire, puis seulement acceptée. Si le modèle n'est pas disponible ou si la sortie reste invalide, le système applique un fallback déterministe explicite défini dans `generator.py` et `templates.py`.

## 4. Pourquoi ce n’est pas une génération LLM directe non contrôlée
Le projet n'utilise pas un LLM comme boîte noire indépendante. Le modèle est appelé uniquement après récupération RAG, avec un prompt enrichi par les documents Top-k, des labels autorisés, un schéma JSON strict, une validation locale et une boucle de réparation. Les templates locaux restent un baseline et un fallback documenté, pas le module final principal.

## 5. Format de sortie `generation_result`
La sortie principale du module est un dictionnaire `generation_result` contenant notamment:
- `generated_rule`
- `attack_type`
- `syntax_validation`
- `valid_rule`
- `validation_errors`
- `detected_options`
- `missing_options`
- `false_positive_risk`
- `false_positive_score`
- `risk_factors`
- `improvement_suggestions`
- `explanation`
- `source_doc_ids`
- `retrieved_context_used`
- `hallucination_risk`
- `option_coverage`
- `model_name`
- `generation_mode`
- `repair_attempts`
- `prompt_variant`

Ce format permet de conserver la compatibilité avec le reste du projet tout en ajoutant des métadonnées utiles pour l'analyse.

## 6. Validation syntaxique et runtime
La validation locale vérifie une forme Snort-like crédible avant export ou affichage. Les contrôles portent notamment sur:
- l'action de règle, par exemple `alert`
- le protocole, par exemple `tcp`, `udp`, `icmp` ou `ip`
- l'opérateur de direction
- la structure des ports source et destination
- la présence de `msg`
- la présence de `sid`
- la présence de `rev`
- la présence de `classtype`
- l'équilibre des parenthèses
- l'extraction et la cohérence des options Snort

Le validateur local filtre les sorties incohérentes, mais il ne remplace pas un moteur Snort réel. Pour l'état courant du projet, les règles Snort 3 exportées dans `data/processed/person1_rules_snort3.rules` sont aussi validées avec le wrapper Docker `tools/snort3-docker` et la configuration `/home/snorty/snort3/etc/snort/snort.lua`. Les résultats sont enregistrés dans `results/snort_runtime_validation.csv`.

## 7. Explication automatique
Le module génère aussi une explication textuelle courte pour justifier la règle retenue. Cette explication peut mentionner:
- le protocole ciblé
- les ports utilisés
- la présence éventuelle de `flow`
- les indicateurs `content` ou `pcre`
- la présence d'un `detection_filter`
- le `classtype` choisi

Cette explication aide à relier la règle produite à l'intention initiale de la requête et aux exemples récupérés.

## 8. Optimisation des faux positifs
Le contrôle des faux positifs repose sur des heuristiques locales dans `false_positive.py`. Le module cherche en particulier à éviter:
- les règles trop générales
- l'absence de `flow` pour certaines attaques TCP ou web
- les ports trop larges alors qu'un service cible est connu
- l'absence de `content` ou `pcre`
- l'absence de `detection_filter` ou `threshold` quand une logique répétitive est attendue
- la génération d'une alerte pour du trafic bénin

Quand la requête décrit un comportement légitime, le système retourne `NO_RULE_RECOMMENDED`. Ce choix est traité comme une recommandation valide, avec un risque de faux positifs nul, afin d'éviter de transformer du trafic normal en alerte artificielle.

Le contrôle empirique disponible reste limité au laboratoire: `results/pcap_test_results.csv` vérifie que les PCAPs d'attaque déclenchent des alertes et que le scénario `benign_traffic` ne déclenche pas d'alerte. `results/network_log_integration_eval.csv` utilise les logs synthétiques académiques, tandis que `results/real_lab_log_integration_eval.csv` utilise les logs de laboratoire contrôlé de `data/logs/real_lab_logs/`.

## 9. Artefacts produits
Les artefacts directement liés à ce module sont:
- `src/snort_rag/generator.py`
- `src/snort_rag/llm_clients.py`
- `src/snort_rag/prompting.py`
- `src/snort_rag/llm_generator.py`
- `src/snort_rag/rule_parser.py`
- `src/snort_rag/templates.py`
- `src/snort_rag/false_positive.py`
- `results/generated_rule_examples.csv`
- `results/false_positive_analysis.csv`
- `results/snort_runtime_validation.csv`
- `results/pcap_test_results.csv`
- `results/network_log_integration_eval.csv`
- `results/real_lab_log_integration_eval.csv`
- `data/logs/real_lab_logs/`
- `tests/test_generator.py`
- `tests/test_log_integration_eval.py`
- `tests/test_real_log_integration.py`

## 10. Limites
Ce module présente les limites suivantes:
- les logs de `data/logs/sample_network_logs.csv` sont synthétiques et académiques
- les logs de `data/logs/real_lab_logs/` sont de vrais artefacts de laboratoire contrôlé, mais pas des logs de production d'entreprise
- Snort runtime reste l'autorité finale pour la syntaxe réelle et les avertissements moteur
- les tests PCAP montrent un comportement dans un corpus de laboratoire limité, pas une étude complète en environnement opérationnel
- certaines sorties LLM sont rejetées par validation stricte et remplacées par un fallback déterministe, ce qui est volontaire pour la sécurité et la reproductibilité

Si Snort Docker n'est pas disponible dans un environnement cible, les résultats runtime doivent être déclarés `SKIPPED` ou en échec; ils ne doivent pas être simulés.
