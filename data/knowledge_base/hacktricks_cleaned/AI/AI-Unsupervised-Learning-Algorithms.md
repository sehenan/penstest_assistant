---
source_name: HackTricks
source_url: https://book.hacktricks.xyz/AI/AI-Unsupervised-Learning-Algorithms
source_date: '2024-01-15'
cve_tags: []
chunk_id: ''
---

# Unsupervised Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Unsupervised Learning

Unsupervised learning is a type of machine learning where the model is trained on data without labeled responses. The goal is to find patterns, structures, or relationships within the data. Unlike supervised learning, where the model learns from labeled examples, unsupervised learning algorithms work with unlabeled data.
Unsupervised learning is often used for tasks such as clustering, dimensionality reduction, and anomaly detection. It can help discover hidden patterns in data, group similar items together, or reduce the complexity of the data while preserving its essential features.

### K-Means Clustering

K-Means is a centroid-based clustering algorithm that partitions data into K clusters by assigning each point to the nearest cluster mean. The algorithm works as follows:
1. **Initialization**: Choose K initial cluster centers (centroids), often randomly or via smarter methods like k-means++
2. **Assignment**: Assign each data point to the nearest centroid based on a distance metric (e.g., Euclidean distance).
3. **Update**: Recalculate the centroids by taking the mean of all data points assigned to each cluster.
4. **Repeat**: Steps 2–3 are repeated until cluster assignments stabilize (centroids no longer move significantly).

> [!TIP]
> *Use cases in cybersecurity:* K-Means is used for intrusion detection by clustering network events. For example, researchers applied K-Means to the KDD Cup 99 intrusion dataset and found it effectively partitioned traffic into normal vs. attack clusters. In practice, security analysts might cluster log entries or user behavior data to find groups of similar activity; any points that don’t belong to a well-formed cluster might indicate anomalies (e.g. a new malware variant forming its own small cluster). K-Means can also help malware family classification by grouping binaries based on behavior profiles or feature vectors.

#### Selection of K
The number of clusters (K) is a hyperparameter that needs to be defined before running the algorithm. Techniques like the Elbow Method or Silhouette Score can help determine an appropriate value for K by evaluating the clustering performance:

- **Elbow Method**: Plot the sum of squared distances from each point to its assigned cluster centroid as a function of K. Look for an "elbow" point where the rate of decrease sharply changes, indicating a suitable number of clusters.
- **Silhouette Score**: Calculate the silhouette score for different values of K. A higher silhouette score indicates better-defined clusters.

#### Assumptions and Limitations

K-Means assumes that **clusters are spherical and equally sized**, which may not hold true for all datasets. It is sensitive to the initial placement of centroids and can converge to local minima. Additionally, K-Means is not suitable for datasets with varying densities or non-globular shapes and features with different scales. Preprocessing steps like normalization or standardization may be necessary to ensure that all features contribute equally to the distance calculations.

### DBSCAN (Density-Based Spatial Clustering of Applications with Noise)

DBSCAN is a density-based clustering algorithm that groups together points that are closely packed together while marking points in low-density regions as outliers. It is particularly useful for datasets with varying densities and non-spherical shapes.

DBSCAN works by defining two parameters:
- **Epsilon (ε)**: The maximum distance between two points to be considered part of the same cluster.
- **MinPts**: The minimum number of points required to form a dense region (core point).

DBSCAN identifies core points, border points, and noise points:
- **Core Point**: A point with at least MinPts neighbors within ε distance.
- **Border Point**: A point that is within ε distance of a core point but has fewer than MinPts neighbors.
- **Noise Point**: A point that is neither a core point nor a border point.

Clustering proceeds by picking an unvisited core point, marking it as a new cluster, then recursively adding all points density-reachable from it (core points and their neighbors, etc.). Border points get added to the cluster of a nearby core. After expanding all reachable points, DBSCAN moves to another unvisited core to start a new cluster. Points not reached by any core remain labeled as noise.

> [!TIP]
> *Use cases in cybersecurity:* DBSCAN is useful for anomaly detection in network traffic. For instance, normal user activity might form one or more dense clusters in feature space, while novel attack behaviors appear as scattered points that DBSCAN will label as noise (outliers). It has been used to cluster network flow records, where it can detect port scans or denial-of-service traffic as sparse regions of points. Another application is grouping malware variants: if most samples cluster by families but a few don’t fit anywhere, those few could be zero-day malware. The ability to flag noise means security teams can focus on investigating those outliers.

#### Assumptions and Limitations

**Assumptions & Strengths:**: DBSCAN does not assume spherical clusters – it can find arbitrarily shaped clusters (even chain-like or adjacent clusters). It automatically determines the number of clusters based on data density and can effectively identify outliers as noise. This makes it powerful for real-world data with irregular shapes and noise. It’s robust to outliers (unlike K-Means, which forces them into clusters). It works well when clusters have roughly uniform density.

**Limitations**: DBSCAN’s performance depends on choosing appropriate ε and MinPts values. It may struggle with data that has varying densities – a single ε cannot accommodate both dense and sparse clusters. If ε is too small, it labels most points as noise; too large, and clusters may merge incorrectly. Also, DBSCAN can be inefficient on very large datasets (naively $O(n^2)$, though spatial indexing can help). In high-dimensional feature spaces, the concept of “distance within ε” may become less meaningful (the curse of dimensionality), and DBSCAN may need careful parameter tuning or may fail to find intuitive clusters. Despite these, extensions like HDBSCAN address some issues (like varying density).

### HDBSCAN (Hierarchical Density-Based Spatial Clustering of Applications with Noise)

**HDBSCAN** is an extension of DBSCAN that removes the need to pick a single global `eps` value and is able to recover clusters of **different density** by building a hierarchy of density-connected components and then condensing it.  Compared with vanilla DBSCAN it usually

* extracts more intuitive clusters when some clusters are dense and others are sparse,
* has only one real hyper-parameter (`min_cluster_size`) and a sensible default,
* gives every point a cluster‐membership *probability* and an **outlier score** (`outlier_scores_`), which is extremely handy for threat-hunting dashboards.

> [!TIP]
> *Use cases in cybersecurity:* HDBSCAN is very popular in modern threat-hunting pipelines – you will often see it inside notebook-based hunting playbooks shipped with commercial XDR suites.  One practical recipe is to cluster HTTP beaconing traffic during IR: user-agent, interval and URI length often form several tight groups of legitimate software updaters while C2 beacons remain as tiny low-density clusters or as pure noise.

<details>
<summary>Example – Finding beaconing C2 channels</summary>

```python
import pandas as pd
from hdbscan import HDBSCAN
from sklearn.preprocessing import StandardScaler

# df has features extracted from proxy logs
features = [
    "avg_interval",      # seconds between requests
    "uri_length_mean",   # average URI length
    "user_agent_entropy" # Shannon entropy of UA string
]
X = StandardScaler().fit_transform(df[features])

hdb = HDBSCAN(min_cluster_size=15,  # at least 15 similar beacons to be a group
              metric="euclidean",
              prediction_data=True)
labels = hdb.fit_predict(X)

df["cluster"] = labels
# Anything with label == -1 is noise → inspect as potential C2
suspects = df[df["cluster"] == -1]
print("Suspect beacon count:", len(suspects))
```

</details>

---

### Robustness and Security Considerations – Poisoning & Adversarial Attacks (2023-2025)

Recent work has shown that **unsupervised learners are *not* immune to active attackers**:

* **Data-poisoning against anomaly detectors.**  Chen *et al.* (IEEE S&P 2024) demonstrated that adding as little as 3 % crafted traffic can shift the decision boundary of Isolation Forest and ECOD so that real attacks look normal.  The authors released an open-source PoC (`udo-poison`) that automatically synthesises poison points.
* **Backdooring clustering models.**  The *BadCME* technique (BlackHat EU 2023) implants a tiny trigger pattern; whenever that trigger appears, a K-Means-based detector quietly places the event inside a “benign” cluster.
* **Evasion of DBSCAN/HDBSCAN.**  A 2025 academic pre-print from KU Leuven showed that an attacker can craft beaconing patterns that purposely fall into density gaps, effectively hiding inside *noise* labels.

Mitigations that are gaining traction:

1. **Model sanitisation / TRIM.**  Before every retraining epoch, discard the 1–2 % highest-loss points (trimmed maximum likelihood) to make poisoning dramatically harder.
2. **Consensus ensembling.**  Combine several heterogeneous detectors (e.g., Isolation Forest + GMM + ECOD) and raise an alert if *any* model flags a point. Research indicates this raises the attacker’s cost by >10×.
3. **Distance-based defence for clustering.**  Re-compute clusters with `k` different random seeds and ignore points that constantly hop clusters.

---

### Modern Open-Source Tooling (2024-2025)

* **PyOD 2.x** (released May 2024) added *ECOD*, *COPOD* and GPU-accelerated *AutoFormer* detectors.  It now ships a `benchmark` sub-command that lets you compare 30+ algorithms on your dataset with **one line of code**:
  ```bash
  pyod benchmark --input logs.csv --label attack --n_jobs 8
  ```
* **Anomalib v1.5** (Feb 2025) focuses on vision but also contains a generic **PatchCore** implementation – handy for screenshot-based phishing page detection.
* **scikit-learn 1.5** (Nov 2024) finally exposes `score_samples` for *HDBSCAN* via the new `cluster.HDBSCAN` wrapper, so you do not need the external contrib package when on Python 3.12.

<details>
<summary>Quick PyOD example – ECOD + Isolation Forest ensemble</summary>

```python
from pyod.models import ECOD, IForest
from pyod.utils.data import generate_data, evaluate_print
from pyod.utils.example import visualize

X_train, y_train, X_test, y_test = generate_data(
    n_train=5000, n_test=1000, n_features=16,
    contamination=0.02, random_state=42)

models = [ECOD(), IForest()]

# majority vote – flag if any model thinks it is anomalous
anomaly_scores = sum(m.fit(X_train).decision_function(X_test) for m in models) / len(models)

evaluate_print("Ensemble", y_test, anomaly_scores)
```

</details>

## References

- [HDBSCAN – Hierarchical density-based clustering](https://github.com/scikit-learn-contrib/hdbscan)
- Chen, X. *et al.* “On the Vulnerability of Unsupervised Anomaly Detection to Data Poisoning.” *IEEE Symposium on Security and Privacy*, 2024.

{{#include ../banners/hacktricks-training.md}}