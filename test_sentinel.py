import unittest
import json
import os
os.makedirs('data', exist_ok=True)
os.makedirs('logs', exist_ok=True)
os.makedirs('retraining', exist_ok=True)
os.makedirs('config', exist_ok=True)

from unittest.mock import patch

from live_sentinel import extract_features, handle_high_tier_threat
from scoring_matrix import score_event
from self_healing_responder import respond

class TestSentinel(unittest.TestCase):
    def setUp(self):
        os.makedirs('data', exist_ok=True)
        os.makedirs('logs', exist_ok=True)
        os.makedirs('retraining', exist_ok=True)

    def test_feature_extraction(self):
        stats = {'login': 50, 'patient': 0, 'total': 50}
        features = extract_features(stats)
        self.assertIn('failed_logins', features)
        self.assertIn('ehr_access_per_hour', features)
        self.assertIn('cpu_usage', features)
        self.assertEqual(features['failed_logins'], 50)
        self.assertEqual(features['attack_type'], 'brute_force')

    def test_threat_tier_classification(self):
        features = {'failed_logins': 50, 'cpu_usage': 0.95, 'ehr_access_per_hour': 0, 'attack_type': 'brute_force', 'asset_type': 'workstation'}
        res = score_event(features)
        self.assertEqual(res['tier'], 'High')
        self.assertGreater(res['raw_score'], 0.7)

    def test_blockchain_integrity(self):
        if os.path.exists('data/audit_chain.json'):
            os.remove('data/audit_chain.json')
            
        features = {'failed_logins': 1, 'cpu_usage': 0.1, 'ehr_access_per_hour': 0, 'attack_type': 'normal', 'asset_type': 'workstation'}
        
        # Block 1
        res1 = score_event(features)
        respond(res1)
        
        # Block 2
        res2 = score_event(features)
        respond(res2)
        
        chain = json.load(open('data/audit_chain.json'))
        
        # Corrupt Block 2 (which is chain[-1] before res3)
        chain[-1]['tier'] = 'High' 
        with open('data/audit_chain.json', 'w') as f:
            json.dump(chain, f)
            
        # Try Block 3
        res3 = score_event(features)
        resp = respond(res3)
        self.assertEqual(resp.get("status"), "HALTED_CORRUPTION")

    @patch('live_sentinel.get_notifier')
    def test_telegram_timeout_fallback(self, mock_get_notifier):
        mock_notifier = mock_get_notifier.return_value
        mock_notifier.request_authorization.return_value = "TIMEOUT"
        
        features = {'failed_logins': 50, 'cpu_usage': 0.95, 'ehr_access_per_hour': 0, 'attack_type': 'brute_force', 'asset_type': 'workstation'}
        res = score_event(features)
        
        handle_high_tier_threat("1.2.3.4", features, res, "Test Alert")
        
        mock_notifier.send_summary.assert_called()
        self.assertTrue(any("AUTO-ESCALATION" in str(call) for call in mock_notifier.send_summary.call_args_list))


if __name__ == '__main__':
    unittest.main()
