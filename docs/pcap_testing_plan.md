# Plan de test PCAP

Les tests PCAP constituent une validation comportementale future des règles exportées pour Person 1. Ils sont distincts de la pré-validation locale du script et distincts d'un simple contrôle statique de syntaxe Snort.

Le validateur local peut rejeter des règles Snort-like manifestement faibles, incohérentes ou trop génériques, mais il ne peut pas démontrer à lui seul:
- qu'une règle déclenche sur le trafic réellement visé
- qu'une règle évite des faux positifs sur du trafic bénin
- qu'une règle se comporte correctement avec un vrai moteur Snort, une vraie configuration et de vrais flux réseau

Aucun résultat PCAP ne doit être affirmé dans la documentation du projet tant que le replay PCAP n'a pas été réellement exécuté et observé avec Snort.

## Principe général

Workflow recommandé:
1. Valider d'abord la syntaxe et les avertissements moteur avec `scripts/validate_rules_with_snort.sh`.
2. Préparer un ensemble de PCAP synthétiques en laboratoire, un par scénario d'attaque principal et plusieurs PCAP bénins de contrôle.
3. Exécuter Snort avec `data/processed/person1_rules.rules` sur chaque PCAP.
4. Collecter les alertes, les non-détections et les déclenchements inattendus.
5. Réviser les règles si le comportement observé ne correspond pas à l'objectif de détection.

Variables d'exécution recommandées:

```bash
export SNORT_CONFIG="${SNORT_CONFIG:-/usr/local/etc/snort/snort.lua}"
```

## Cas de test détaillés

### 1. `port_scan`

Objectif du test:
Vérifier qu'un balayage SYN répété depuis une source externe vers plusieurs ports internes déclenche une alerte de type reconnaissance.

Trafic PCAP attendu:
Un hôte externe envoie plusieurs paquets TCP SYN vers un hôte interne sur des ports variés comme `21`, `22`, `80`, `443` dans une courte fenêtre temporelle.

Règle ou catégorie attendue:
Catégorie `port_scan`, en particulier les règles avec `flags:S` et `detection_filter`.

Comportement attendu:
Snort doit générer une ou plusieurs alertes cohérentes avec la détection d'un scan répétitif, sans exiger un échange TCP complet.

Contrôle de faux positif:
Rejouer un PCAP de connexions TCP légitimes isolées vers quelques ports sans cadence de scan. Une connexion normale ou quelques SYN dispersés ne devraient pas produire le même motif d'alerte.

Example command:

```bash
snort -c "$SNORT_CONFIG" -R data/processed/person1_rules.rules -r tests/pcaps/port_scan.pcap -A alert_fast
```

### 2. `ssh_bruteforce`

Objectif du test:
Vérifier qu'une série de tentatives répétées d'authentification SSH vers `22` ou `2222` depuis la même source déclenche la règle attendue.

Trafic PCAP attendu:
Des sessions TCP vers un service SSH interne, avec plusieurs tentatives rapprochées depuis une même IP externe. Le flux doit contenir des marqueurs plausibles de session SSH.

Règle ou catégorie attendue:
Catégorie `ssh_bruteforce`, règles TCP vers `22` ou `2222` avec `flow:to_server,established`, `content:"SSH-"` et `detection_filter`.

Comportement attendu:
Snort doit alerter quand le seuil de répétition est franchi, en cohérence avec un bruteforce ou une tentative répétée de connexion SSH.

Contrôle de faux positif:
Tester un PCAP avec une unique connexion SSH administrative légitime ou quelques connexions non répétitives. Le trafic d'administration normal ne devrait pas être assimilé à un bruteforce.

Example command:

```bash
snort -c "$SNORT_CONFIG" -R data/processed/person1_rules.rules -r tests/pcaps/ssh_bruteforce.pcap -A alert_fast
```

### 3. `sql_injection`

Objectif du test:
Vérifier que des requêtes web contenant des motifs SQL classiques comme `UNION SELECT`, `' OR 1=1 --` ou `SLEEP(5)` sont détectées.

Trafic PCAP attendu:
Des requêtes HTTP ou HTTPS déchiffrées en laboratoire vers une application web interne sur `80`, `443` ou `8080`, avec les chaînes SQL injectées dans l'URI, les paramètres ou le corps.

Règle ou catégorie attendue:
Catégorie `sql_injection`, règles TCP web avec `flow:to_server,established` et `content` ciblant les motifs SQL.

Comportement attendu:
Snort doit produire une alerte sur les requêtes contenant les charges utiles SQL malveillantes prévues par la règle.

Contrôle de faux positif:
Rejouer des requêtes HTTP légitimes contenant les mots `select` ou `union` dans un contexte non malveillant, par exemple de la documentation ou des exemples pédagogiques. L'objectif est d'évaluer si les règles sont trop sensibles à des mots isolés.

Example command:

```bash
snort -c "$SNORT_CONFIG" -R data/processed/person1_rules.rules -r tests/pcaps/sql_injection.pcap -A alert_fast
```

### 4. `xss`

Objectif du test:
Vérifier que des charges utiles XSS typiques comme `<script>`, `onerror=` ou `<svg/onload=...>` sont détectées dans du trafic web.

Trafic PCAP attendu:
Des requêtes HTTP vers une application web interne contenant des balises ou attributs XSS dans l'URI, les paramètres, les formulaires ou les entêtes applicatifs.

Règle ou catégorie attendue:
Catégorie `xss`, règles TCP web avec `content` et éventuellement `pcre` sur des motifs HTML/JavaScript malveillants.

Comportement attendu:
Snort doit alerter sur les charges utiles XSS explicitement représentées dans les règles.

Contrôle de faux positif:
Tester un PCAP de navigation ou de développement web légitime contenant des fragments HTML non malveillants, voire des chaînes affichées comme texte brut dans une page d'aide. L'objectif est de mesurer le risque de déclenchement sur du contenu bénin.

Example command:

```bash
snort -c "$SNORT_CONFIG" -R data/processed/person1_rules.rules -r tests/pcaps/xss.pcap -A alert_fast
```

### 5. `command_injection`

Objectif du test:
Vérifier que des séquences de type `;wget`, `&& curl` ou `|/bin/sh` insérées dans du trafic web sont détectées comme tentative d'injection de commande.

Trafic PCAP attendu:
Des requêtes HTTP vers un service web interne, avec paramètres ou corps contenant des séparateurs de commandes shell et des appels réseau suspects.

Règle ou catégorie attendue:
Catégorie `command_injection`, règles TCP web avec `flow:to_server,established` et `content` sur les séquences d'injection.

Comportement attendu:
Snort doit générer une alerte lorsqu'une chaîne représentative d'injection de commande est présente dans le flux applicatif.

Contrôle de faux positif:
Rejouer du trafic web d'administration, de documentation ou de formation contenant des snippets shell affichés comme texte. Cela permet de vérifier que la règle ne confond pas exemple textuel et tentative réelle selon le contexte réseau disponible.

Example command:

```bash
snort -c "$SNORT_CONFIG" -R data/processed/person1_rules.rules -r tests/pcaps/command_injection.pcap -A alert_fast
```

### 6. `directory_traversal`

Objectif du test:
Vérifier que des motifs comme `../`, `%2f`, `passwd` ou `win.ini` dans des requêtes web déclenchent les règles de traversal.

Trafic PCAP attendu:
Des requêtes HTTP vers une application web interne cherchant à accéder à des chemins sensibles via traversal, y compris des variantes encodées.

Règle ou catégorie attendue:
Catégorie `directory_traversal`, règles TCP web avec `content:"../"` et `pcre` sur les variantes encodées ou les fichiers sensibles.

Comportement attendu:
Snort doit alerter sur les chemins de traversal explicites et leurs variantes proches prévues par les expressions de détection.

Contrôle de faux positif:
Tester des requêtes web bénignes vers des chemins comportant plusieurs répertoires ou des noms de fichiers ressemblants sans intention de traversal. Cela aide à voir si la règle est trop large.

Example command:

```bash
snort -c "$SNORT_CONFIG" -R data/processed/person1_rules.rules -r tests/pcaps/directory_traversal.pcap -A alert_fast
```

### 7. `dns_tunneling`

Objectif du test:
Vérifier qu'un trafic DNS anormalement verbeux ou contenant de longues charges utiles de type sous-domaines encodés déclenche les règles prévues.

Trafic PCAP attendu:
Des requêtes DNS sortantes du réseau interne vers l'extérieur, potentiellement sur `53`, avec labels longs, répétitifs ou chargés de données artificielles.

Règle ou catégorie attendue:
Catégorie `dns_tunneling`, règles `dns`, `udp` ou `tcp` utilisant `content`, `nocase` et/ou `dsize:>70`.

Comportement attendu:
Snort doit détecter les requêtes DNS de longueur suspecte ou contenant les marqueurs ciblés par les règles.

Contrôle de faux positif:
Rejouer des requêtes DNS bénignes mais longues, comme certains domaines légitimes complexes, CDN, télémétrie ou mises à jour. Cela permet de vérifier si le seuil de taille est trop agressif.

Example command:

```bash
snort -c "$SNORT_CONFIG" -R data/processed/person1_rules.rules -r tests/pcaps/dns_tunneling.pcap -A alert_fast
```

### 8. `icmp_sweep`

Objectif du test:
Vérifier qu'une série rapide de requêtes ICMP Echo vers plusieurs hôtes internes ou avec fréquence anormale déclenche une détection de balayage.

Trafic PCAP attendu:
Des paquets ICMP Echo Request venant d'une source externe vers plusieurs cibles internes, avec une cadence suffisante pour franchir le `detection_filter`.

Règle ou catégorie attendue:
Catégorie `icmp_sweep`, règles ICMP avec `dsize` et `detection_filter`.

Comportement attendu:
Snort doit produire une alerte quand le volume ou la cadence d'ICMP correspond à un sweep plutôt qu'à un simple ping isolé.

Contrôle de faux positif:
Rejouer un PCAP avec quelques pings de supervision, de diagnostic ou de monitoring. Le trafic ICMP normal à faible cadence ne devrait pas être classé comme sweep.

Example command:

```bash
snort -c "$SNORT_CONFIG" -R data/processed/person1_rules.rules -r tests/pcaps/icmp_sweep.pcap -A alert_fast
```

### 9. `malware_c2`

Objectif du test:
Vérifier qu'un trafic sortant périodique ou des chemins applicatifs de type `/beacon`, `/gate.php` ou `/sync/api` déclenchent les règles de command-and-control.

Trafic PCAP attendu:
Des connexions du réseau interne vers l'extérieur sur `80`, `443`, `8080`, `8443` ou éventuellement `53`, avec répétition temporelle et chemins réseau compatibles avec un beacon.

Règle ou catégorie attendue:
Catégorie `malware_c2`, règles d'egress utilisant `flow:to_server,established`, `content` et `detection_filter`.

Comportement attendu:
Snort doit alerter sur le trafic périodique ou sur les motifs applicatifs explicitement modélisés comme beaconing/C2.

Contrôle de faux positif:
Rejouer du trafic applicatif légitime vers des API externes, synchronisations cloud, agents de mise à jour ou outils de monitoring. Cela permet d'évaluer la confusion possible entre beacon malveillant et télémétrie normale.

Example command:

```bash
snort -c "$SNORT_CONFIG" -R data/processed/person1_rules.rules -r tests/pcaps/malware_c2.pcap -A alert_fast
```

### 10. `benign_traffic`

Objectif du test:
Vérifier que du trafic légitime représentatif du dataset `benign_traffic` ne déclenche pas les règles exportées, puisque ces lignes utilisent `NO_RULE_RECOMMENDED` et ne doivent pas produire d'alertes dédiées.

Trafic PCAP attendu:
Des flux normaux de navigation web, SSH d'administration, DNS usuel, monitoring ICMP, sauvegarde ou health checks, sans charges utiles explicitement malveillantes.

Règle ou catégorie attendue:
Aucune règle dédiée `benign_traffic`. Le test sert de baseline de non-détection face à l'ensemble de `data/processed/person1_rules.rules`.

Comportement attendu:
Aucune alerte idéalement. Si des alertes apparaissent, elles doivent être examinées comme faux positifs potentiels ou comme signe que les règles sont trop larges.

Contrôle de faux positif:
Comparer plusieurs PCAP bénins couvrant différents usages réels de laboratoire: navigation web simple, requêtes DNS classiques, quelques pings, synchronisation logicielle et accès SSH administratifs normaux.

Example command:

```bash
snort -c "$SNORT_CONFIG" -R data/processed/person1_rules.rules -r tests/pcaps/benign_traffic.pcap -A alert_fast
```

## Interprétation des résultats

Un résultat de validation utile doit documenter au minimum:
- le nom du PCAP rejoué
- la date d'exécution
- la commande Snort utilisée
- le nombre d'alertes produites
- les SID déclenchés
- les cas attendus non détectés
- les cas bénins détectés par erreur

Sans cette exécution réelle, il ne faut pas présenter les règles comme validées opérationnellement. La pré-validation locale reste un filtre de qualité, mais Snort et les PCAP demeurent la référence finale pour le comportement de détection.
