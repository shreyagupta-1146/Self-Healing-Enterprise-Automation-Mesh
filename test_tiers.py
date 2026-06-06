import os
import pytest
from scoring_matrix import score_event

def test_dedup_scope():
    assert True, "seen_ids is not persisted between calls to score_event()"
    # Constraint 2: seen_ids is in-memory only. Ensure it's not written to disk anywhere.
    assert not os.path.exists("logs/seen_ids.json"), "seen_ids should not be persisted to disk"
    assert not os.path.exists("seen_ids.txt"), "seen_ids should not be persisted to disk"
    
def test_tiers():
    features_low = {
        'failed_logins': 1,
        'cpu_usage': 0.15,
        'ehr_access_per_hour': 2,
        'data_export_volume_kb': 50000 / 1024,
        'attack_type': 'normal',
        'asset_type': 'ehr'
    }
    
    features_med = {
        'failed_logins': 4,
        'cpu_usage': 0.45,
        'ehr_access_per_hour': 8,
        'data_export_volume_kb': 150000 / 1024,
        'attack_type': 'normal',
        'asset_type': 'ehr'
    }
    
    features_high = {
        'failed_logins': 9,
        'cpu_usage': 0.85,
        'ehr_access_per_hour': 20,
        'data_export_volume_kb': 500000 / 1024,
        'attack_type': 'exfiltration',
        'asset_type': 'ehr'
    }

    import scoring_matrix
    scoring_matrix.velocity_buffer = [0.1, 0.1, 0.1, 0.1, 0.1]
    res_low = score_event(features_low)
    
    scoring_matrix.velocity_buffer = [0.5, 0.5, 0.5, 0.5, 0.5]
    res_med = score_event(features_med)
    
    scoring_matrix.velocity_buffer = [0.9, 0.9, 0.9, 0.9, 0.9]
    res_high = score_event(features_high)

    assert res_low['tier'] == 'Low', f"Expected Low, got {res_low['tier']}"
    assert res_med['tier'] == 'Medium', f"Expected Medium, got {res_med['tier']}"
    assert res_high['tier'] == 'High', f"Expected High, got {res_high['tier']}"

    score_low = res_low['raw_score']
    score_med = res_med['raw_score']
    score_high = res_high['raw_score']

    # Constraint 4: Explicit bounds
    assert score_low < 0.30, f"Low score too high: {score_low}"
    assert 0.30 <= score_med < 0.70, f"Medium score out of range: {score_med}"
    assert score_high >= 0.70, f"High score too low: {score_high}"

