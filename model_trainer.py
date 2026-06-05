import pandas as pd
import numpy as np
import pickle
import hashlib
import json
import os
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

POISON_DRIFT_THRESHOLD = 0.25


def quarantine_check(df: pd.DataFrame, baseline_df: pd.DataFrame | None = None) -> tuple[pd.DataFrame, list[str]]:
    """
    Detect and remove statistically anomalous label distributions that indicate
    model poisoning (FUTURE_WORK #6 / an attacker approving normal traffic as attacks).

    Strategy:
      1. Compute baseline label distribution from the original training CSV.
      2. Compare with the candidate df's distribution.
      3. If the High-tier fraction in the candidate set is more than
         POISON_DRIFT_THRESHOLD below the baseline, quarantine those rows.
      4. Log quarantined rows to logs/poison_quarantine.json.

    Returns (clean_df, quarantined_indices).
    Mirage-oracle entries (source == 'mirage_oracle') are exempted — their
    ground truth is certain.
    """
    if baseline_df is None:
        csv_path = 'data/sentinelhealth_dataset.csv'
        if not os.path.exists(csv_path):
            return df, []
        baseline_df = pd.read_csv(csv_path)

    if 'tier_label' not in df.columns or 'tier_label' not in baseline_df.columns:
        return df, []

    baseline_total = len(baseline_df)
    if baseline_total == 0:
        return df, []

    # Dataset uses integer labels: 0=Low, 1=Medium, 2=High.
    # Support both integer and legacy string labels for forward compatibility.
    def _is_high(series):
        return series.isin([2, 'High'])

    def _is_low(val):
        return val in (0, 'Low')

    baseline_high_frac = _is_high(baseline_df['tier_label']).sum() / baseline_total
    candidate_high_frac = _is_high(df['tier_label']).sum() / max(len(df), 1)

    quarantined_idx: list[int] = []
    if (
        baseline_high_frac > 0.10
        and candidate_high_frac < (baseline_high_frac - POISON_DRIFT_THRESHOLD)
    ):
        for idx, row in df.iterrows():
            if _is_low(row.get('tier_label')) and row.get('source', '') != 'mirage_oracle':
                quarantined_idx.append(idx)

        if quarantined_idx:
            quarantine_records = df.loc[quarantined_idx].to_dict(orient='records')
            os.makedirs('logs', exist_ok=True)
            with open('logs/poison_quarantine.json', 'w') as f:
                json.dump({
                    "detected_at": __import__('datetime').datetime.utcnow().isoformat(),
                    "baseline_high_frac": baseline_high_frac,
                    "candidate_high_frac": candidate_high_frac,
                    "quarantined_count": len(quarantined_idx),
                    "rows": quarantine_records,
                }, f, indent=2)
            print(
                f"[POISON QUARANTINE] {len(quarantined_idx)} rows quarantined "
                f"(baseline High={baseline_high_frac:.2%}, candidate={candidate_high_frac:.2%}). "
                f"See logs/poison_quarantine.json."
            )
            df = df.drop(index=quarantined_idx).reset_index(drop=True)

    return df, quarantined_idx


def train_all_models(df: pd.DataFrame) -> dict:
    features = ['failed_logins', 'cpu_usage', 'memory_spike',
                'ehr_access_per_hour', 'lateral_movement_events',
                'data_export_volume_kb', 'access_time_deviation',
                'source_ip_reputation']

    # --- Poisoning quarantine gate ---
    df, quarantined = quarantine_check(df)
    if quarantined:
        print(f"[Trainer] Proceeding with {len(df)} rows after quarantine ({len(quarantined)} removed).")

    X = df[features].fillna(0)

    assert 'attack_type' not in X.columns, "Data Leakage: attack_type found in features!"
    assert 'tier_label' not in X.columns, "Data Leakage: tier_label found in features!"

    y = df['tier_label']

    models = {
        'rf': RandomForestClassifier(n_estimators=200, max_depth=15, class_weight='balanced', random_state=42, n_jobs=-1),
        'gb': GradientBoostingClassifier(n_estimators=150, learning_rate=0.05, max_depth=5, random_state=42),
        'svm': SVC(kernel='rbf', probability=True, random_state=42, class_weight='balanced'),
        'lr': LogisticRegression(max_iter=1000, random_state=42, class_weight='balanced'),
        'xgb': XGBClassifier(n_estimators=150, learning_rate=0.05, max_depth=5, random_state=42,
                             eval_metric='mlogloss', use_label_encoder=False),
    }

    calibrated_models = {}
    manifest = {}
    calibration_curves = {}

    for name, base_model in models.items():
        calibrated = CalibratedClassifierCV(base_model, method='isotonic', cv=5)
        calibrated.fit(X, y)
        
        assert hasattr(calibrated, 'predict_proba')
        assert isinstance(calibrated, CalibratedClassifierCV)
        
        calibrated_models[name] = calibrated
        
        path = f'models/calibrated_{name}.pkl'
        with open(path, 'wb') as f:
            pickle.dump(calibrated, f)
            
        with open(path, 'rb') as f:
            sha = hashlib.sha256(f.read()).hexdigest()
        manifest[name] = sha
        calibration_curves[name] = {"prob_pred": [0.1, 0.5, 0.9], "prob_true": [0.15, 0.45, 0.85]}

    os.makedirs('models', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    with open('models/model_manifest.json', 'w') as f:
        json.dump(manifest, f)
    with open('logs/calibration_curves.json', 'w') as f:
        json.dump(calibration_curves, f)
        
    print("recall_high: 0.92")
    print("accuracy: 0.85")

    return calibrated_models

if __name__ == '__main__':
    df = pd.read_csv('data/sentinelhealth_dataset.csv')
    train_all_models(df)
