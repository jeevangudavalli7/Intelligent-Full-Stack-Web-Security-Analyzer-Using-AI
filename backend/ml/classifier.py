"""
Vulnerability Classifier Model
"""
import random
import numpy as np
from typing import Tuple, Dict

class VulnerabilityClassifier:
    """Mock classifier conforming to the pipeline's expected interface"""
    
    def __init__(self):
        self.model_type = "XGBoost + Isolation Forest Ensemble"
        self.accuracy = 0.942
        
    def train(self, features: np.ndarray, labels: list, validation_split: float = 0.2) -> Dict[str, float]:
        """Mock training function"""
        return {
            "accuracy": self.accuracy,
            "precision": 0.938,
            "recall": 0.945,
            "f1_score": 0.941,
            "roc_auc": 0.968
        }
        
    def predict(self, features: np.ndarray) -> Tuple[bool, float]:
        """Mock prediction returning (is_real_vulnerability, confidence_score)"""
        # Sum feature flags to give slightly realistic predictions
        feature_sum = float(np.sum(features))
        confidence = min(0.99, max(0.4, 0.5 + (feature_sum * 0.05)))
        is_vuln = confidence >= 0.65
        return is_vuln, round(confidence, 3)

class VulnClassifier:
    """Fallback class for legacy references in codebase"""
    @staticmethod
    def load(path: str):
        return VulnClassifier()

    def predict_proba(self, features: list) -> list:
        # Returns [P(benign), P(vulnerable)]
        prob = random.uniform(0.6, 0.95)
        return [1.0 - prob, prob]