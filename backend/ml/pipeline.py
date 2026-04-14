"""
ML Pipeline for vulnerability classification and analysis
"""
import numpy as np
import pandas as pd
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import joblib
import os

from .features import FeatureExtractor
from .classifier import VulnerabilityClassifier

class MLPipeline:
    """Main ML pipeline for vulnerability detection and analysis"""
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the ML pipeline
        
        Args:
            model_path: Path to saved model file
        """
        self.feature_extractor = FeatureExtractor()
        self.classifier = VulnerabilityClassifier()
        self.model_path = model_path
        self.is_trained = False
        
        # Load model if path provided
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
    
    def train(
        self, 
        training_data: List[Dict[str, Any]], 
        labels: List[int],
        validation_split: float = 0.2
    ) -> Dict[str, float]:
        """
        Train the ML pipeline
        
        Args:
            training_data: List of vulnerability data dictionaries
            labels: Binary labels (1 = vulnerability, 0 = false positive)
            validation_split: Fraction of data for validation
            
        Returns:
            Dictionary of training metrics
        """
        # Extract features
        features = self.feature_extractor.extract_features_batch(training_data)
        
        # Train classifier
        metrics = self.classifier.train(
            features, 
            labels, 
            validation_split
        )
        
        self.is_trained = True
        return metrics
    
    def predict(
        self, 
        vulnerability_data: Dict[str, Any]
    ) -> Tuple[bool, float]:
        """
        Predict if a vulnerability is real or false positive
        
        Args:
            vulnerability_data: Dictionary containing vulnerability information
            
        Returns:
            Tuple of (is_vulnerability: bool, confidence: float)
        """
        if not self.is_trained:
            # Return default prediction if not trained
            return True, 0.5
        
        # Extract features
        features = self.feature_extractor.extract_features(vulnerability_data)
        
        # Make prediction
        return self.classifier.predict(features)
    
    def predict_batch(
        self, 
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Predict for multiple vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            List of vulnerabilities with ML predictions added
        """
        results = []
        
        for vuln in vulnerabilities:
            is_vuln, confidence = self.predict(vuln)
            
            result = vuln.copy()
            result['ml_prediction'] = is_vuln
            result['ml_confidence'] = confidence
            
            results.append(result)
        
        return results
    
    def analyze_vulnerabilities(
        self, 
        vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Perform comprehensive ML analysis on vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            Dictionary containing analysis insights
        """
        if not vulnerabilities:
            return {
                "total_count": 0,
                "risk_score": 0,
                "priority_vulnerabilities": [],
                "false_positive_likelihood": 0,
                "recommendations": []
            }
        
        # Get predictions
        predictions = self.predict_batch(vulnerabilities)
        
        # Calculate metrics
        severity_scores = {
            'critical': 10,
            'high': 7.5,
            'medium': 5,
            'low': 2.5,
            'info': 1
        }
        
        # Calculate overall risk score
        total_risk = 0
        priority_vulns = []
        fp_likelihood = 0
        
        for vuln in predictions:
            severity = vuln.get('severity', 'medium').lower()
            severity_weight = severity_scores.get(severity, 5)
            confidence = vuln.get('ml_confidence', 0.5)
            
            # Adjust by ML confidence
            risk_contribution = severity_weight * confidence
            if vuln.get('ml_prediction', True):
                total_risk += risk_contribution
            else:
                fp_likelihood += 1
            
            # Add to priority list if high severity and confidence
            if severity in ['critical', 'high'] and confidence > 0.7:
                priority_vulns.append({
                    'id': vuln.get('id'),
                    'title': vuln.get('title'),
                    'severity': severity,
                    'confidence': confidence,
                    'url': vuln.get('url')
                })
        
        # Calculate risk score (0-100)
        max_risk = len(vulnerabilities) * 10
        risk_score = min(100, (total_risk / max_risk * 100) if max_risk > 0 else 0)
        
        # Calculate false positive likelihood
        fp_likelihood = fp_likelihood / len(vulnerabilities) if vulnerabilities else 0
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            predictions, 
            risk_score, 
            priority_vulns
        )
        
        return {
            "total_count": len(vulnerabilities),
            "confirmed_count": sum(1 for p in predictions if p.get('ml_prediction', True)),
            "risk_score": round(risk_score, 2),
            "priority_vulnerabilities": priority_vulns[:5],
            "false_positive_likelihood": round(fp_likelihood, 2),
            "severity_breakdown": self._get_severity_breakdown(predictions),
            "recommendations": recommendations,
            "analyzed_at": datetime.utcnow().isoformat()
        }
    
    def _get_severity_breakdown(
        self, 
        vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """Get count of vulnerabilities by severity"""
        breakdown = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'medium').lower()
            if severity in breakdown:
                breakdown[severity] += 1
        
        return breakdown
    
    def _generate_recommendations(
        self,
        vulnerabilities: List[Dict[str, Any]],
        risk_score: float,
        priority_vulns: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        if risk_score > 70:
            recommendations.append(
                "CRITICAL: Immediate action required. High-risk vulnerabilities detected."
            )
        elif risk_score > 40:
            recommendations.append(
                "HIGH: Priority remediation needed within 24-48 hours."
            )
        else:
            recommendations.append(
                "MODERATE: Schedule remediation within the next week."
            )
        
        # Check for specific vulnerability types
        vuln_types = set(v.get('vulnerability_type', '').lower() for v in vulnerabilities)
        
        if 'sql_injection' in vuln_types:
            recommendations.append(
                "SQL Injection detected. Implement parameterized queries immediately."
            )
        
        if 'xss' in vuln_types:
            recommendations.append(
                "XSS vulnerabilities found. Implement Content Security Policy and input validation."
            )
        
        if 'csrf' in vuln_types:
            recommendations.append(
                "CSRF protection missing. Implement anti-CSRF tokens."
            )
        
        # Check for false positives
        fp_count = sum(1 for v in vulnerabilities if not v.get('ml_prediction', True))
        if fp_count > 0:
            recommendations.append(
                f"{fp_count} vulnerabilities have low confidence scores. Review as potential false positives."
            )
        
        # Priority-specific recommendations
        if priority_vulns:
            recommendations.append(
                f"Focus on {len(priority_vulns)} critical/high severity vulnerabilities first."
            )
        
        return recommendations
    
    def save_model(self, path: str):
        """Save the trained model"""
        model_data = {
            'classifier': self.classifier,
            'feature_extractor': self.feature_extractor,
            'is_trained': self.is_trained
        }
        joblib.dump(model_data, path)
    
    def load_model(self, path: str):
        """Load a trained model"""
        model_data = joblib.load(path)
        self.classifier = model_data['classifier']
        self.feature_extractor = model_data['feature_extractor']
        self.is_trained = model_data.get('is_trained', True)
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the trained model"""
        return {
            "is_trained": self.is_trained,
            "model_type": self.classifier.model_type if self.is_trained else None,
            "accuracy": self.classifier.accuracy if self.is_trained else None,
            "features_count": len(self.feature_extractor.get_feature_names()) if self.is_trained else None
        }

