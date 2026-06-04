---
source_name: HackTricks
source_url: https://book.hacktricks.xyz/AI/AI-Supervised-Learning-Algorithms
source_date: '2024-01-15'
cve_tags: []
chunk_id: ''
---

# Supervised Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Basic Information

Supervised learning uses labeled data to train models that can make predictions on new, unseen inputs. In cybersecurity, supervised machine learning is widely applied to tasks such as intrusion detection (classifying network traffic as *normal* or *attack*), malware detection (distinguishing malicious software from benign), phishing detection (identifying fraudulent websites or emails), and spam filtering, among others. Each algorithm has its strengths and is suited to different types of problems (classification or regression). Below we review key supervised learning algorithms, explain how they work, and demonstrate their use on real cybersecurity datasets. We also discuss how combining models (ensemble learning) can often improve predictive performance.

## Algorithms

-   **Linear Regression:** A fundamental regression algorithm for predicting numeric outcomes by fitting a linear equation to data.

-   **Logistic Regression:** A classification algorithm (despite its name) that uses a logistic function to model the probability of a binary outcome.

-   **Decision Trees:** Tree-structured models that split data by features to make predictions; often used for their interpretability.

-   **Random Forests:** An ensemble of decision trees (via bagging) that improves accuracy and reduces overfitting.

-   **Support Vector Machines (SVM):** Max-margin classifiers that find the optimal separating hyperplane; can use kernels for non-linear data.

-   **Naive Bayes:** A probabilistic classifier based on Bayes' theorem with an assumption of feature independence, famously used in spam filtering.

-   **k-Nearest Neighbors (k-NN):** A simple "instance-based" classifier that labels a sample based on the majority class of its nearest neighbors.

-   **Gradient Boosting Machines:** Ensemble models (e.g., XGBoost, LightGBM) that build a strong predictor by sequentially adding weaker learners (typically decision trees).

Each section below provides an improved description of the algorithm and a **Python code example** using libraries like `pandas` and `scikit-learn` (and `PyTorch` for the neural network example). The examples use publicly available cybersecurity datasets (such as NSL-KDD for intrusion detection and a Phishing Websites dataset) and follow a consistent structure:

1.  **Load the dataset** (download via URL if available).

2.  **Preprocess the data** (e.g. encode categorical features, scale values, split into train/test sets).

3.  **Train the model** on the training data.

4.  **Evaluate** on a test set using metrics: accuracy, precision, recall, F1-score, and ROC AUC for classification (and mean squared error for regression).

Let's dive into each algorithm:

### Linear Regression

Linear regression is a **regression** algorithm used to predict continuous numeric values. It assumes a linear relationship between the input features (independent variables) and the output (dependent variable). The model attempts to fit a straight line (or hyperplane in higher dimensions) that best describes the relationship between features and the target. This is typically done by minimizing the sum of squared errors between predicted and actual values (Ordinary Least Squares method).

The simplest for to represent linear regression is with a line:

```plaintext
y = mx + b
```

Where:

- `y` is the predicted value (output)
- `m` is the slope of the line (coefficient)
- `x` is the input feature
- `b` is the y-intercept

The goal of linear regression is to find the best-fitting line that minimizes the difference between the predicted values and the actual values in the dataset. Of course, this is very simple, it would be a straight line sepparating 2 categories, but if more dimensions are added, the line becomes more complex:

```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```

> [!TIP]
> *Use cases in cybersecurity:* Linear regression itself is less common for core security tasks (which are often classification), but it can be applied to predict numerical outcomes. For example, one could use linear regression to **predict the volume of network traffic** or **estimate the number of attacks in a time period** based on historical data. It could also predict a risk score or the expected time until detection of an attack, given certain system metrics. In practice, classification algorithms (like logistic regression or trees) are more frequently used for detecting intrusions or malware, but linear regression serves as a foundation and is useful for regression-oriented analyses.

#### **Key characteristics of Linear Regression:**

-   **Type of Problem:** Regression (predicting continuous values). Not suited for direct classification unless a threshold is applied to the output.

-   **Interpretability:** High -- coefficients are straightforward to interpret, showing the linear effect of each feature.

-   **Advantages:** Simple and fast; a good baseline for regression tasks; works well when the true relationship is approximately linear.

-   **Limitations:** Can't capture complex or non-linear relationships (without manual feature engineering); prone to underfitting if relationships are non-linear; sensitive to outliers which can skew the results.

-   **Finding the Best Fit:** To find the best fit line that sepparates the possible categories, we use a method called **Ordinary Least Squares (OLS)**. This method minimizes the sum of the squared differences between the observed values and the values predicted by the linear model.

### Decision Trees

A decision tree is a versatile **supervised learning algorithm** that can be used for both classification and regression tasks. It learns a hierarchical tree-like model of decisions based on the features of the data. Each internal node of the tree represents a test on a particular feature, each branch represents an outcome of that test, and each leaf node represents a predicted class (for classification) or value (for regression).

To build a tree, algorithms like CART (Classification and Regression Tree) use measures such as **Gini impurity** or **information gain (entropy)** to choose the best feature and threshold to split the data at each step. The goal at each split is to partition the data to increase the homogeneity of the target variable in the resulting subsets (for classification, each node aims to be as pure as possible, containing predominantly a single class).

Decision trees are **highly interpretable** -- one can follow the path from root to leaf to understand the logic behind a prediction (e.g., *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"*). This is valuable in cybersecurity for explaining why a certain alert was raised. Trees can naturally handle both numerical and categorical data and require little preprocessing (e.g., feature scaling is not needed).

However, a single decision tree can easily overfit the training data, especially if grown deep (many splits). Techniques like pruning (limiting tree depth or requiring a minimum number of samples per leaf) are often used to prevent overfitting.

There are 3 main components of a decision tree:
- **Root Node**: The top node of the tree, representing the entire dataset.
- **Internal Nodes**: Nodes that represent features and decisions based on those features.
- **Leaf Nodes**: Nodes that represent the final outcome or prediction.

A tree might end up looking like this:

```plaintext
          [Root Node]
              /   \
         [Node A]  [Node B]
          /   \      /   \
     [Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```

> [!TIP]
> *Use cases in cybersecurity:* Decision trees have been used in intrusion detection systems to derive **rules** for identifying attacks. For example, early IDS like ID3/C4.5-based systems would generate human-readable rules to distinguish normal vs. malicious traffic. They are also used in malware analysis to decide if a file is malicious based on its attributes (file size, section entropy, API calls, etc.). The clarity of decision trees makes them useful when transparency is needed -- an analyst can inspect the tree to validate the detection logic.

#### **Key characteristics of Decision Trees:**

-   **Type of Problem:** Both classification and regression. Commonly used for classification of attacks vs. normal traffic, etc.

-   **Interpretability:** Very high -- the model's decisions can be visualized and understood as a set of if-then rules. This is a major advantage in security for trust and verification of model behavior.

-   **Advantages:** Can capture non-linear relationships and interactions between features (each split can be seen as an interaction). No need to scale features or one-hot encode categorical variables -- trees handle those natively. Fast inference (prediction is just following a path in the tree).

-   **Limitations:** Prone to overfitting if not controlled (a deep tree can memorize the training set). They can be unstable -- small changes in data might lead to a different tree structure. As single models, their accuracy might not match more advanced methods (ensembles like Random Forests typically perform better by reducing variance).

-   **Finding the Best Split:**
  - **Gini Impurity**: Measures the impurity of a node. A lower Gini impurity indicates a better split. The formula is:
  
  ```plaintext
  Gini = 1 - Σ(p_i^2)
  ```

  Where `p_i` is the proportion of instances in class `i`.
  
  - **Entropy**: Measures the uncertainty in the dataset. A lower entropy indicates a better split. The formula is:

  ```plaintext
  Entropy = -Σ(p_i * log2(p_i))
  ```

  Where `p_i` is the proportion of instances in class `i`.
  
  - **Information Gain**: The reduction in entropy or Gini impurity after a split. The higher the information gain, the better the split. It is calculated as:

  ```plaintext
  Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
  ```

Moreover, a tree is ended when:
- All instances in a node belong to the same class. This might lead to overfitting.
- The maximum depth (hardcoded) of the tree is reached. This is a way to prevent overfitting.
- The number of instances in a node is below a certain threshold. This is also a way to prevent overfitting.
- The information gain from further splits is below a certain threshold. This is also a way to prevent overfitting.

### Support Vector Machines (SVM)

Support Vector Machines are powerful supervised learning models used primarily for classification (and also regression as SVR). An SVM tries to find the **optimal separating hyperplane** that maximizes the margin between two classes. Only a subset of training points (the "support vectors" closest to the boundary) determines the position of this hyperplane. By maximizing the margin (distance between support vectors and the hyperplane), SVMs tend to achieve good generalization.

Key to SVM's power is the ability to use **kernel functions** to handle non-linear relationships. The data can be implicitly transformed into a higher-dimensional feature space where a linear separator might exist. Common kernels include polynomial, radial basis function (RBF), and sigmoid. For example, if network traffic classes aren't linearly separable in the raw feature space, an RBF kernel can map them into a higher dimension where the SVM finds a linear split (which corresponds to a non-linear boundary in original space). The flexibility of choosing kernels allows SVMs to tackle a variety of problems.

SVMs are known to perform well in situations with high-dimensional feature spaces (like text data or malware opcode sequences) and in cases where the number of features is large relative to number of samples. They were popular in many early cybersecurity applications such as malware classification and anomaly-based intrusion detection in the 2000s, often showing high accuracy.

However, SVMs do not scale easily to very large datasets (training complexity is super-linear in number of samples, and memory usage can be high since it may need to store many support vectors). In practice, for tasks like network intrusion detection with millions of records, SVM might be too slow without careful subsampling or using approximate methods.

#### **Key characteristics of SVM:**

-   **Type of Problem:** Classification (binary or multiclass via one-vs-one/one-vs-rest) and regression variants. Often used in binary classification with clear margin separation.

-   **Interpretability:** Medium -- SVMs are not as interpretable as decision trees or logistic regression. While you can identify which data points are support vectors and get some sense of which features might be influential (through the weights in the linear kernel case), in practice SVMs (especially with non-linear kernels) are treated as black-box classifiers.

-   **Advantages:** Effective in high-dimensional spaces; can model complex decision boundaries with kernel trick; robust to overfitting if margin is maximized (especially with a proper regularization parameter C); works well even when classes are not separated by a large distance (finds best compromise boundary).

-   **Limitations:** **Computationally intensive** for large datasets (both training and prediction scale poorly as data grows). Requires careful tuning of kernel and regularization parameters (C, kernel type, gamma for RBF, etc.). Doesn't directly provide probabilistic outputs (though one can use Platt scaling to get probabilities). Also, SVMs can be sensitive to the choice of kernel parameters --- a poor choice can lead to underfit or overfit.

*Use cases in cybersecurity:* SVMs have been used in **malware detection** (e.g., classifying files based on extracted features or opcode sequences), **network anomaly detection** (classifying traffic as normal vs malicious), and **phishing detection** (using features of URLs). For instance, an SVM could take features of an email (counts of certain keywords, sender reputation scores, etc.) and classify it as phishing or legitimate. They have also been applied to **intrusion detection** on feature sets like KDD, often achieving high accuracy at the cost of computation.

### Gradient Boosting Machines (e.g., XGBoost)

Gradient Boosting Machines are among the most powerful algorithms for structured data. **Gradient boosting** refers to the technique of building an ensemble of weak learners (often decision trees) in a sequential manner, where each new model corrects the errors of the previous ensemble. Unlike bagging (Random Forests) which build trees in parallel and average them, boosting builds trees *one by one*, each focusing more on the instances that previous trees mis-predicted.

The most popular implementations in recent years are **XGBoost**, **LightGBM**, and **CatBoost**, all of which are gradient boosting decision tree (GBDT) libraries. They have been extremely successful in machine learning competitions and applications, often **achieving state-of-the-art performance on tabular datasets**. In cybersecurity, researchers and practitioners have used gradient boosted trees for tasks like **malware detection** (using features extracted from files or runtime behavior) and **network intrusion detection**. For example, a gradient boosting model can combine many weak rules (trees) such as "if many SYN packets and unusual port -> likely scan" into a strong composite detector that accounts for many subtle patterns.

Why are boosted trees so effective? Each tree in the sequence is trained on the *residual errors* (gradients) of the current ensemble's predictions. This way, the model gradually **"boosts"** the areas where it's weak. The use of decision trees as base learners means the final model can capture complex interactions and non-linear relations. Also, boosting inherently has a form of built-in regularization: by adding many small trees (and using a learning rate to scale their contributions), it often generalizes well without huge overfitting, provided proper parameters are chosen.

#### **Key characteristics of Gradient Boosting:**

-   **Type of Problem:** Primarily classification and regression. In security, usually classification (e.g., binary classify a connection or file). It handles binary, multi-class (with appropriate loss), and even ranking problems.

-   **Interpretability:** Low to medium. While a single boosted tree is small, a full model might have hundreds of trees, which is not human-interpretable as a whole. However, like Random Forest, it can provide feature importance scores, and tools like SHAP (SHapley Additive exPlanations) can be used to interpret individual predictions to some extent.

-   **Advantages:** Often the **best performing** algorithm for structured/tabular data. Can detect complex patterns and interactions. Has many tuning knobs (number of trees, depth of trees, learning rate, regularization terms) to tailor model complexity and prevent overfitting. Modern implementations are optimized for speed (e.g., XGBoost uses second-order gradient info and efficient data structures). Tends to handle imbalanced data better when combined with appropriate loss functions or by adjusting sample weights.

-   **Limitations:** More complex to tune than simpler models; training can be slow if trees are deep or number of trees is large (though still usually faster than training a comparable deep neural network on the same data). The model can overfit if not tuned (e.g., too many deep trees with insufficient regularization). Because of many hyperparameters, using gradient boosting effectively may require more expertise or experimentation. Also, like tree-based methods, it doesn't inherently handle very sparse high-dimensional data as efficiently as linear models or Naive Bayes (though it can still be applied, e.g., in text classification, but might not be first choice without feature engineering).

> [!TIP]
> *Use cases in cybersecurity:* Almost anywhere a decision tree or random forest could be used, a gradient boosting model might achieve better accuracy. For example, **Microsoft's malware detection** competitions have seen heavy use of XGBoost on engineered features from binary files. **Network intrusion detection** research often reports top results with GBDTs (e.g., XGBoost on CIC-IDS2017 or UNSW-NB15 datasets). These models can take a wide range of features (protocol types, frequency of certain events, statistical features of traffic, etc.) and combine them to detect threats. In phishing detection, gradient boosting can combine lexical features of URLs, domain reputation features, and page content features to achieve very high accuracy. The ensemble approach helps cover many corner cases and subtleties in the data.

<details>
<summary>Example -- XGBoost for Phishing Detection:</summary>
We'll use a gradient boosting classifier on the phishing dataset. To keep things simple and self-contained, we'll use `sklearn.ensemble.GradientBoostingClassifier` (which is a slower but straightforward implementation). Normally, one might use `xgboost` or `lightgbm` libraries for better performance and additional features. We will train the model and evaluate it similarly to before.

```python
import pandas as pd
from sklearn.datasets import fetch_openml
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# 1️⃣ Load the “Phishing Websites” data directly from OpenML
data = fetch_openml(data_id=4534, as_frame=True)   # or data_name="PhishingWebsites"
df   = data.frame

# 2️⃣ Separate features/target & make sure everything is numeric
X = df.drop(columns=["Result"])
y = df["Result"].astype(int).apply(lambda v: 1 if v == 1 else 0)  # map {-1,1} → {0,1}

# (If any column is still object‑typed, coerce it to numeric.)
X = X.apply(pd.to_numeric, errors="coerce").fillna(0)

# 3️⃣ Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X.values, y, test_size=0.20, random_state=42
)

# 4️⃣ Gradient Boosting model
model = GradientBoostingClassifier(
    n_estimators=100, learning_rate=0.1, max_depth=3, random_state=42
)
model.fit(X_train, y_train)

# 5️⃣ Evaluation
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

print(f"Accuracy:  {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall:    {recall_score(y_test, y_pred):.3f}")
print(f"F1‑score:  {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC:   {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy:  0.951
Precision: 0.949
Recall:    0.965
F1‑score:  0.957
ROC AUC:   0.990
"""
```

The gradient boosting model will likely achieve very high accuracy and AUC on this phishing dataset (often these models can exceed 95% accuracy with proper tuning on such data, as seen in literature. This demonstrates why GBDTs are considered *"the state of the art model for tabular dataset"* -- they often outperform simpler algorithms by capturing complex patterns. In a cybersecurity context, this could mean catching more phishing sites or attacks with fewer misses. Of course, one must be cautious about overfitting -- we would typically use techniques like cross-validation and monitor performance on a validation set when developing such a model for deployment.

</details>

### Combining Models: Ensemble Learning and Stacking

Ensemble learning is a strategy of **combining multiple models** to improve overall performance. We already saw specific ensemble methods: Random Forest (an ensemble of trees via bagging) and Gradient Boosting (an ensemble of trees via sequential boosting). But ensembles can be created in other ways too, such as **voting ensembles** or **stacked generalization (stacking)**. The main idea is that different models may capture different patterns or have different weaknesses; by combining them, we can **compensate for each model's errors with another's strengths**.

-   **Voting Ensemble:** In a simple voting classifier, we train multiple diverse models (say, a logistic regression, a decision tree, and an SVM) and have them vote on the final prediction (majority vote for classification). If we weight the votes (e.g., higher weight to more accurate models), it's a weighted voting scheme. This typically improves performance when the individual models are reasonably good and independent -- the ensemble reduces the risk of an individual model's mistake since others may correct it. It's like having a panel of experts rather than a single opinion.

-   **Stacking (Stacked Ensemble):** Stacking goes a step further. Instead of a simple vote, it trains a **meta-model** to **learn how to best combine the predictions** of base models. For example, you train 3 different classifiers (base learners), then feed their outputs (or probabilities) as features into a meta-classifier (often a simple model like logistic regression) that learns the optimal way to blend them. The meta-model is trained on a validation set or via cross-validation to avoid overfitting. Stacking can often outperform simple voting by learning *which models to trust more in which circumstances*. In cybersecurity, one model might be better at catching network scans while another is better at catching malware beaconing; a stacking model could learn to rely on each appropriately.

Ensembles, whether by voting or stacking, tend to **boost accuracy** and robustness. The downside is increased complexity and sometimes reduced interpretability (though some ensemble approaches like an average of decision trees can still provide some insight, e.g., feature importance). In practice, if operational constraints allow, using an ensemble can lead to higher detection rates. Many winning solutions in cybersecurity challenges (and Kaggle competitions in general) use ensemble techniques to squeeze out the last bit of performance.

<details>
<summary>Example -- Voting Ensemble for Phishing Detection:</summary>
To illustrate model stacking, let's combine a few of the models we discussed on the phishing dataset. We'll use a logistic regression, a decision tree, and a k-NN as base learners, and use a Random Forest as a meta-learner to aggregate their predictions. The meta-learner will be trained on the outputs of the base learners (using cross-validation on the training set). We expect the stacked model to perform as well as or slightly better than the individual models.

```python
import pandas as pd
from sklearn.datasets import fetch_openml
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import StackingClassifier, RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score,
                             recall_score, f1_score, roc_auc_score)

# ──────────────────────────────────────────────
# 1️⃣  LOAD DATASET (OpenML id 4534)
# ──────────────────────────────────────────────
data = fetch_openml(data_id=4534, as_frame=True)     # “PhishingWebsites”
df   = data.frame

# Target mapping:  1 → legitimate (0),   0/‑1 → phishing (1)
y = (df["Result"].astype(int) != 1).astype(int)
X = df.drop(columns=["Result"])

# Train / test split (stratified to keep class balance)
X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y)

# ──────────────────────────────────────────────
# 2️⃣  DEFINE BASE LEARNERS
#     • LogisticRegression and k‑NN need scaling ➜ wrap them
#       in a Pipeline(StandardScaler → model) so that scaling
#       happens inside each CV fold of StackingClassifier.
# ──────────────────────────────────────────────
base_learners = [
    ('lr',  make_pipeline(StandardScaler(),
                          LogisticRegression(max_iter=1000,
                                             solver='lbfgs',
                                             random_state=42))),
    ('dt',  DecisionTreeClassifier(max_depth=5, random_state=42)),
    ('knn', make_pipeline(StandardScaler(),
                          KNeighborsClassifier(n_neighbors=5)))
]

# Meta‑learner (level‑2 model)
meta_learner = RandomForestClassifier(n_estimators=50, random_state=42)

stack_model = StackingClassifier(
    estimators      = base_learners,
    final_estimator = meta_learner,
    cv              = 5,        # 5‑fold CV to create meta‑features
    passthrough     = False     # only base learners’ predictions go to meta‑learner
)

# ──────────────────────────────────────────────
# 3️⃣  TRAIN ENSEMBLE
# ──────────────────────────────────────────────
stack_model.fit(X_train, y_train)

# ──────────────────────────────────────────────
# 4️⃣  EVALUATE
# ──────────────────────────────────────────────
y_pred = stack_model.predict(X_test)
y_prob = stack_model.predict_proba(X_test)[:, 1]   # P(phishing)

print(f"Accuracy : {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall   : {recall_score(y_test, y_pred):.3f}")
print(f"F1‑score : {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC  : {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy : 0.954
Precision: 0.951
Recall   : 0.946
F1‑score : 0.948
ROC AUC  : 0.992
"""
```
The stacked ensemble takes advantage of the complementary strengths of the base models. For instance, logistic regression might handle linear aspects of the data, the decision tree might capture specific rule-like interactions, and k-NN might excel in local neighborhoods of the feature space. The meta-model (a random forest here) can learn how to weigh these inputs. The resulting metrics often show an improvement (even if slight) over any single model's metrics. In our phishing example, if logistic alone had an F1 of say 0.95 and the tree 0.94, the stack might achieve 0.96 by picking up where each model errs.

Ensemble methods like this demonstrate the principle that *"combining multiple models typically leads to better generalization"*. In cybersecurity, this can be implemented by having multiple detection engines (one might be rule-based, one machine learning, one anomaly-based) and then a layer that aggregates their alerts -- effectively a form of ensemble -- to make a final decision with higher confidence. When deploying such systems, one must consider the added complexity and ensure that the ensemble doesn't become too hard to manage or explain. But from an accuracy standpoint, ensembles and stacking are powerful tools for improving model performance.

</details>

## References

- [https://madhuramiah.medium.com/logistic-regression-6e55553cc003](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [https://www.geeksforgeeks.org/decision-tree-introduction-example/](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [https://www.ibm.com/think/topics/support-vector-machine](https://www.ibm.com/think/topics/support-vector-machine)
- [https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [https://zvelo.com/ai-and-machine-learning-in-cybersecurity/](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [https://www.ibm.com/think/topics/knn](https://www.ibm.com/think/topics/knn)
- [https://www.ibm.com/think/topics/knn](https://www.ibm.com/think/topics/knn)
- [https://arxiv.org/pdf/2101.02552](https://arxiv.org/pdf/2101.02552)
- [https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
- [https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
- [https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)
- [https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)

{{#include ../banners/hacktricks-training.md}}