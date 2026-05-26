# Méthodologie du dataset

## Pourquoi le dataset est personnel
Le dataset officiel de Person 1 a été construit à la main pour ce projet. Les descriptions, logs simulés, contextes de faux positifs et explications ont été rédigés localement par nous, puis relus pour rester petits, contrôlés et vérifiables. Les anciens fichiers `snort_generated_dataset.*` relevaient d'une expérimentation séparée et ne font pas partie du dataset final soumis.

## Création des exemples manuels
Les lignes `manual` correspondent aux exemples de base les plus importants pour chaque type d'attaque. Chaque exemple contient une description naturelle, un log simulé crédible, un type d'attaque cohérent, un niveau de sévérité, un contexte de faux positifs et une explication attendue.

## Création des variations `synthetic_manual_variation`
Les variations `synthetic_manual_variation` ont été écrites à partir des exemples manuels, sans copier un dataset public. Chaque variation change au moins deux éléments utiles au RAG: le style de description, le payload observé, le format de log, le contexte de faux positifs, la sévérité ou l'explication.

## Labels utilisés
Les labels métier utilisés sont `port_scan`, `ssh_bruteforce`, `sql_injection`, `xss`, `command_injection`, `directory_traversal`, `dns_tunneling`, `icmp_sweep`, `malware_c2` et `benign_traffic`. Les familles d'attaque ont été fixées de façon cohérente pour faciliter le filtrage et la récupération.

## Simulation des logs
Les logs ont été simulés dans plusieurs formats réalistes: Apache access log, Nginx access log, SSH auth log, firewall log, Zeek-like conn log, Zeek-like dns log, proxy log, WAF log, IDS-style log et ICMP sweep log. L'objectif est de fournir des mots-clés récupérables par un moteur de recherche RAG sans prétendre reproduire tous les champs d'un environnement de production.

## Règles Snort-like
Les règles de `snort_rule_reference` sont des règles Snort-like éducatives, écrites pour rester simples et lisibles. Elles contiennent `alert`, `msg`, une condition de détection, `classtype`, `sid` et `rev`. Elles ne remplacent pas une validation Snort réelle.

## Séparation avec la base de connaissance de règles fiables
Les règles Snort de confiance stockées dans `data/knowledge_base/` restent une base de connaissance de référence séparée. Elles peuvent aider à comparer une structure de règle, mais elles ne servent pas de dataset principal pour l'apprentissage ou la récupération Person 1.

## Utilité pour la récupération RAG
Le dataset est utile pour la récupération parce qu'il relie des descriptions naturelles variées, des logs simulés, des familles d'attaque, des niveaux de sévérité et des explications attendues. Un moteur de recherche peut donc retrouver des exemples proches même si la requête change de style ou de vocabulaire.

## Limites
Le dataset reste petit et pédagogique. Les logs sont simulés, pas collectés depuis une infrastructure réelle. Les règles Snort-like sont vérifiées structurellement, mais pas encore validées en exécution dans un moteur Snort réel.
