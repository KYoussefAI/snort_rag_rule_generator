# Retrieval et benchmark des embeddings

## Objectif

L'objectif de cette partie est de comparer plusieurs strategies de recuperation Top-k pour le pipeline RAG Snort. Le module de retrieval doit retrouver les exemples les plus pertinents du dataset personnel a partir d'une description d'attaque reseau en langage naturel.

Les methodes comparees sont:
- BM25
- similarite dense TF-IDF
- embeddings Sentence-BERT en similarite cosinus
- embeddings Sentence-BERT avec index FAISS
- TF-IDF avec reranking
- retrieval hybride BM25 + TF-IDF
- retrieval hybride avec reranking
- plusieurs valeurs de alpha pour le score hybride

## Metriques utilisees

Les metriques calculees sont:
- Hit@k: verifie si au moins un document correct apparait dans le Top-k
- Precision@k: mesure la proportion de documents corrects dans le Top-k
- Recall@k: verifie si la classe attendue est retrouvee dans le Top-k
- MRR: mesure le rang du premier document correct
- Latence moyenne: temps moyen de recuperation en millisecondes

## Resultats principaux

Le benchmark montre que la meilleure methode est `hybrid_rerank_best`, qui combine un retrieval hybride BM25 + TF-IDF avec un reranking controle.

A k=3, cette methode obtient:
- Hit@3 = 1.0
- Precision@3 = 1.0
- Recall@3 = 1.0
- MRR = 1.0
- Latence moyenne ~= 3.5 ms

La methode `dense_tfidf_rerank` est plus rapide, mais sa Precision@3 est plus faible. Pour un systeme RAG, la qualite du contexte recupere est prioritaire, car des documents incorrects peuvent degrader la generation de regles Snort.

## Justification du choix final

La methode `hybrid_rerank_best` est retenue car elle garde les avantages du retrieval lexical BM25 et de la similarite dense TF-IDF. Le reranking ameliore le classement final en remontant les documents dont le type d'attaque correspond mieux a la requete.

Ce choix corrige notamment les cas ou le bon type d'attaque etait present dans le Top-3 mais pas au premier rang. Le benchmark montre donc que le reranking ameliore la robustesse du retrieval pour le pipeline RAG.

## Fichiers produits

Les artefacts produits sont:
- `src/snort_rag/retrieval.py`: ajout de la methode `hybrid_rerank_retrieve`
- `src/snort_rag/retrieval.py`: ajout des chemins `sentence_bert_retrieve` et `sentence_bert_faiss_retrieve`
- `scripts/benchmark_retrieval.py`: script de benchmark
- `scripts/plot_retrieval_benchmark.py`: generation du graphique comparatif
- `results/embedding_benchmark.csv`: resultats des metriques
- `results/retrieval_topk_examples.csv`: documents Top-k recuperes pour chaque requete
- `results/retrieval_benchmark_k3_summary.csv`: tableau resume a k=3
- `results/retrieval_benchmark_k3.png`: graphique de comparaison
- `results/retrieval_backend_proof.json`: preuve d'activation runtime du backend Sentence-BERT/FAISS

## Preuve backend

Le fichier `results/embedding_benchmark.csv` contient maintenant les colonnes `backend`, `status`, `sentence_bert_runtime_available`, `faiss_runtime_available`, `sentence_bert_model` et `faiss_enabled`. Cela permet de verifier si une ligne de benchmark a vraiment ete executee avec Sentence-BERT et FAISS, ou si la methode etait indisponible dans l'environnement.
