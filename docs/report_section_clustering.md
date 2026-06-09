# Attack-Family Clustering

The clustering module evaluates whether document vectors naturally group similar attack types and families. It is separate from t-SNE visualization: clustering is performed first, then t-SNE is used only to visualize the selected clustering result.

Run:

```bash
PYTHONPATH=src python scripts/run_clustering_analysis.py
```

Required outputs:

- `results/clustering_metrics.csv`
- `results/clustering_confusion_matrix.csv`
- `results/clustering_tsne.png`

The metrics file reports silhouette, ARI, NMI, homogeneity, completeness, and V-measure for KMeans and Agglomerative clustering over TF-IDF/SVD representations.
