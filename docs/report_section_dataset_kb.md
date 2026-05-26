# Construction du dataset et base de connaissance

Le dataset principal a été construit comme un corpus personnel, petit et contrôlé, afin de respecter la contrainte académique du projet. Nous n'avons pas utilisé Kaggle, de dataset GitHub prêt à l'emploi ni de base pré-étiquetée comme jeu principal. Les exemples ont été écrits par nous en combinant descriptions naturelles, logs simulés, contexte de faux positifs et explications attendues.

Les exemples `manual` servent de noyau de référence. Les lignes `synthetic_manual_variation` sont des variations rédigées localement à partir de ce noyau, en changeant le style linguistique, le payload observé, le format du log, la sévérité ou le contexte. Les labels utilisés couvrent dix catégories: port scan, brute force SSH, SQL injection, XSS, command injection, directory traversal, DNS tunneling, ICMP sweep, malware C2 et trafic bénin.

Les logs ont été simulés dans plusieurs formats proches d'un SOC: Apache, Nginx, firewall, WAF, proxy, Zeek-like, SSH auth et ICMP sweep. Cette diversité améliore la récupération parce qu'un système RAG peut associer une requête en langage naturel à des indices concrets présents dans les logs et aux explications attendues. Le dataset reste néanmoins limité: il est de taille réduite, les données sont simulées et les règles Snort-like doivent encore être testées dans un environnement Snort réel.

La base de connaissance de règles Snort de confiance est gardée séparée du dataset personnel. Cette séparation évite de confondre une ressource de référence externe avec notre corpus principal. Le dataset personnel sert à la récupération et à l'explication; la base de connaissance de confiance sert uniquement d'appui documentaire complémentaire.
