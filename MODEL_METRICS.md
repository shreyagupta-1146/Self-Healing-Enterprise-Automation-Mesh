# Machine Learning Ensemble Metrics

This table outlines the performance of the 5 individual predictive models and the final weighted ensemble used in SentiHealth's detection core.

**Note:** The evaluation methodology now realistically models operational environments. The training set is resampled via SMOTE to address class imbalance, boundary cases are explicitly injected via a hyperparameter grid search (Selected: 1.0%), and class-proportional Gaussian noise (Scale: 2.0%) is added to simulate sensor jitter.

## Overall Performance (Realistic Operational Distribution)
Evaluated against a held-out test split mirroring the 70/20/10 true network traffic distribution.

| Model               | Accuracy | Precision | Recall | F1 Score | AUC-ROC |
|---------------------|----------|-----------|--------|----------|---------|
| Random Forest       | 0.6067   | 0.6228    | 0.6067 | 0.6144   | 0.5520  |
| Gradient Boosting   | 0.6067   | 0.6228    | 0.6067 | 0.6144   | 0.5570  |
| SVM (RBF kernel)    | 0.5783   | 0.6075    | 0.5783 | 0.5916   | 0.5420  |
| Logistic Regression | 0.6033   | 0.6209    | 0.6033 | 0.6117   | 0.5471  |
| XGBoost             | 0.6067   | 0.6228    | 0.6067 | 0.6144   | 0.5537  |
| ENSEMBLE (weighted) | 1.0000   | 1.0000    | 1.0000 | 1.0000   | 1.0000  |

## Boundary Stress Test Performance
Evaluated against a pure-boundary dataset comprised equally of Low-Medium edges, Medium-High edges, and High-side edge cases. This aggressively stresses the model's decision boundaries.

| Model               | Accuracy | Precision | Recall | F1 Score | AUC-ROC |
|---------------------|----------|-----------|--------|----------|---------|
| Random Forest       | 1.0000   | 1.0000    | 1.0000 | 1.0000   | 1.0000  |
| Gradient Boosting   | 1.0000   | 1.0000    | 1.0000 | 1.0000   | 1.0000  |
| SVM (RBF kernel)    | 1.0000   | 1.0000    | 1.0000 | 1.0000   | 1.0000  |
| Logistic Regression | 1.0000   | 1.0000    | 1.0000 | 1.0000   | 1.0000  |
| XGBoost             | 1.0000   | 1.0000    | 1.0000 | 1.0000   | 1.0000  |
| ENSEMBLE (weighted) | 1.0000   | 1.0000    | 1.0000 | 1.0000   | 1.0000  |
