# Génération, validation et contrôle des faux positifs

## 1. Objectif du module
L'objectif de ce module est de produire une règle Snort-like cohérente à partir d'une description textuelle d'attaque réseau, tout en gardant un contrôle local sur la qualité syntaxique, l'explication de la règle et le risque de faux positifs. Le module doit aussi pouvoir recommander explicitement l'absence de règle quand la requête décrit un trafic bénin.

## 2. Entrées
Le module s'appuie sur quatre types d'entrées:
- la requête utilisateur en langage naturel
- les documents Top-k récupérés par le pipeline RAG
- une règle Snort de référence présente dans les documents récupérés quand elle existe
- les logs simulés et le contexte de faux positif déjà présents dans le dataset et utilisés indirectement par la récupération

## 3. Architecture
Le flux suivi par le module est le suivant:

description utilisateur  
→ documents récupérés  
→ prompt ou template contrôlé  
→ règle Snort générée ou sélectionnée  
→ validation syntaxique  
→ explication  
→ analyse des faux positifs

En pratique, si un document récupéré contient déjà une règle Snort-like valide et pertinente pour le type d'attaque détecté, le système préfère cette règle. Sinon, il applique un template local déterministe défini dans le projet.

## 4. Pourquoi ce n’est pas une génération LLM directe
Ce module n'appelle aucun service LLM externe et ne délègue pas la génération finale à une boîte noire. La logique est locale, déterministe et contrôlée par le code du projet. La génération repose soit sur une règle récupérée depuis le corpus, soit sur un template Snort écrit à l'avance dans le dépôt. Le prompt construit dans `generator.py` sert à rendre le pipeline explicable, mais il n'est pas envoyé à une API OpenAI, Claude, Mistral ou Ollama.

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

Ce format permet de conserver la compatibilité avec le reste du projet tout en ajoutant des métadonnées utiles pour l'analyse.

## 6. Validation syntaxique
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

Le validateur reste volontairement local et structurel. Il filtre les sorties incohérentes, mais il ne remplace pas un moteur Snort réel.

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

## 9. Artefacts produits
Les artefacts directement liés à ce module sont:
- `src/snort_rag/generator.py`
- `src/snort_rag/rule_parser.py`
- `src/snort_rag/templates.py`
- `src/snort_rag/false_positive.py`
- `results/generated_rule_examples.csv`
- `results/false_positive_analysis.csv`
- `tests/test_generator.py`

## 10. Limites
Ce module présente trois limites principales:
- la validation effectuée est une validation locale Snort-like seulement
- Snort runtime reste l'autorité finale pour la syntaxe réelle et les avertissements moteur
- des tests PCAP sont nécessaires pour vérifier le comportement réel, la qualité de détection et le niveau de faux positifs

Cette section ne revendique donc pas une validation d'exécution Snort si elle n'a pas été réellement lancée dans l'environnement cible.
