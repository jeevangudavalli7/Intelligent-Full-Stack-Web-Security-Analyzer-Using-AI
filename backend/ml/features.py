"""
Feature Extraction for Vulnerability Classification
"""
import numpy as np
import re
from typing import Dict, Any, List
from urllib.parse import urlparse

class FeatureExtractor:
    """Extract features from vulnerability data for ML classification"""
    
    def __init__(self):
        self.feature_names = [
            # Severity features
            'severity_critical',
            'severity_high',
            'severity_medium',
            'severity_low',
            'severity_info',
            
            # Type features
            'type_sql_injection',
            'type_xss',
            'type_csrf',
            'type_auth_bypass',
            'type_command_injection',
            'type_other',
            
            # URL features
            'url_length',
            'url_has_params',
            'url_has_special_chars',
            'url_has_queries',
            
            # Payload features
            'payload_length',
            'payload_has_sql_keywords',
            'payload_has_script_tags',
            'payload_has_encoding',
            'payload_complexity',
            
            # Context features
            'has_cwe_id',
            'has_cvss_score',
            'cvss_high',
            
            # Evidence features
            'evidence_length',
            'has_error_message',
            'has_stack_trace',
        ]
    
    def extract_features(self, vuln_data: Dict[str, Any]) -> np.ndarray:
        """
        Extract features from a single vulnerability
        
        Args:
            vuln_data: Dictionary containing vulnerability information
            
        Returns:
            Feature vector as numpy array
        """
        features = []
        
        # Severity encoding (one-hot)
        severity = vuln_data.get('severity', 'medium').lower()
        features.extend([
            1 if severity == 'critical' else 0,
            1 if severity == 'high' else 0,
            1 if severity == 'medium' else 0,
            1 if severity == 'low' else 0,
            1 if severity == 'info' else 0,
        ])
        
        # Vulnerability type encoding (one-hot)
        vuln_type = vuln_data.get('vulnerability_type', 'other').lower()
        features.extend([
            1 if 'sql' in vuln_type else 0,
            1 if 'xss' in vuln_type or 'script' in vuln_type else 0,
            1 if 'csrf' in vuln_type else 0,
            1 if 'auth' in vuln_type else 0,
            1 if 'command' in vuln_type or 'inject' in vuln_type else 0,
            1 if not any([x in vuln_type for x in ['sql', 'xss', 'csrf', 'auth', 'command']]) else 0,
        ])
        
        # URL features
        url = vuln_data.get('url', '')
        if url:
            parsed = urlparse(url)
            features.extend([
                len(url),  # URL length
                1 if parsed.query else 0,  # Has parameters
                1 if any(c in url for c in ['<', '>', '"', "'", '&']) else 0,  # Has special chars
                1 if parsed.query and '=' in parsed.query else 0,  # Has query string
            ])
        else:
            features.extend([0, 0, 0, 0])
        
        # Payload features
        payload = vuln_data.get('payload', '')
        features.extend([
            len(payload),  # Payload length
            1 if self._contains_sql_keywords(payload) else 0,  # Has SQL keywords
            1 if self._contains_script_tags(payload) else 0,  # Has script tags
            1 if self._is_encoded(payload) else 0,  # Is encoded
            self._calculate_complexity(payload),  # Complexity score
        ])
        
        # Context features
        features.extend([
            1 if vuln_data.get('cwe_id') else 0,  # Has CWE ID
            1 if vuln_data.get('cvss_score') else 0,  # Has CVSS score
            1 if vuln_data.get('cvss_score', 0) >= 7.0 else 0,  # High CVSS
        ])
        
        # Evidence features
        evidence = vuln_data.get('evidence', '')
        features.extend([
            len(evidence),  # Evidence length
            1 if self._contains_error_message(evidence) else 0,  # Has error message
            1 if self._contains_stack_trace(evidence) else 0,  # Has stack trace
        ])
        
        return np.array(features, dtype=np.float32)
    
    def extract_features_batch(self, vuln_list: List[Dict[str, Any]]) -> np.ndarray:
        """
        Extract features from multiple vulnerabilities
        
        Args:
            vuln_list: List of vulnerability dictionaries
            
        Returns:
            Feature matrix
        """
        features = []
        for vuln in vuln_list:
            features.append(self.extract_features(vuln))
        
        return np.array(features)
    
    def get_feature_names(self) -> List[str]:
        """Get list of feature names"""
        return self.feature_names
    
    def _contains_sql_keywords(self, text: str) -> bool:
        """Check if text contains SQL keywords"""
        sql_keywords = [
            'select', 'insert', 'update', 'delete', 'drop',
            'union', 'from', 'where', 'and', 'or', 'order',
            'by', 'having', 'group', 'table', 'database',
            'information_schema', 'exec', 'execute'
        ]
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in sql_keywords)
    
    def _contains_script_tags(self, text: str) -> bool:
        """Check if text contains script injection patterns"""
        script_patterns = [
            r'<script',
            r'javascript:',
            r'onerror\s*=',
            r'onload\s*=',
            r'onclick\s*=',
            r'onmouse',
            r'<img[^>]*onerror',
            r'<svg[^>]*onload',
            r'alert\(',
            r'eval\(',
        ]
        
        for pattern in script_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    def _is_encoded(self, text: str) -> bool:
        """Check if text is URL or HTML encoded"""
        # URL encoding
        if '%' in text and len(text) % 2 == 0:
            try:
                if all(c in '0123456789ABCDEFabcdef%' for c in text.replace('%', '')):
                    return True
            except:
                pass
        
        # HTML entities
        html_entities = ['<', '>', '&amp;', '&#']
        if any(entity in text for entity in html_entities):
            return True
        
        return False
    
    def _calculate_complexity(self, text: str) -> float:
        """Calculate complexity score of payload"""
        if not text:
            return 0.0
        
        score = 0.0
        
        # Length factor
        score += min(len(text) / 100, 1.0)
        
        # Character diversity
        unique_chars = len(set(text))
        score += min(unique_chars / 50, 1.0)
        
        # Special characters
        special_chars = sum(1 for c in text if c in '<>"\':;=+()[]{}')
        score += min(special_chars / 20, 1.0)
        
        # Encoding indicators
        if self._is_encoded(text):
            score += 0.5
        
        return min(score / 3, 1.0)  # Normalize to 0-1
    
    def _contains_error_message(self, text: str) -> bool:
        """Check if text contains database error messages"""
        error_patterns = [
            r'sql\s*syntax',
            r'mysql',
            r'postgresql',
            r'ORA-\d{5}',
            r'microsoft\s*sql',
            r'sqlite.*error',
            r'warning.*mysql',
            r'fatal\s*error',
            r'uncaught\s*exception',
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    def _contains_stack_trace(self, text: str) -> bool:
        """Check if text contains stack trace"""
        stack_patterns = [
            r'at\s+[\w.$]+\([\w.]+:\d+\)',
            r'Traceback \(most recent call last\)',
            r'Stack\s*Trace',
            r'Exception in thread',
            r'org\.python\.',
            r'java\.lang\.',
            r'PHP\s+Fatal',
        ]
        
        for pattern in stack_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False


class FeatureTransformer:
    """Transform and normalize features"""
    
    @staticmethod
    def normalize(features: np.ndarray, method: str = 'standard') -> np.ndarray:
        """
        Normalize feature values
        
        Args:
            features: Feature matrix
            method: Normalization method ('standard', 'minmax', or 'robust')
            
        Returns:
            Normalized features
        """
        if method == 'standard':
            # Z-score normalization
            mean = np.mean(features, axis=0)
            std = np.std(features, axis=0)
            std[std == 0] = 1  # Avoid division by zero
            return (features - mean) / std
        
        elif method == 'minmax':
            # Min-max normalization
            min_vals = np.min(features, axis=0)
            max_vals = np.max(features, axis=0)
            range_vals = max_vals - min_vals
            range_vals[range_vals == 0] = 1  # Avoid division by zero
            return (features - min_vals) / range_vals
        
        elif method == 'robust':
            # Robust normalization using median and IQR
            median = np.median(features, axis=0)
            q75 = np.percentile(features, 75, axis=0)
            q25 = np.percentile(features, 25, axis=0)
            iqr = q75 - q25
            iqr[iqr == 0] = 1  # Avoid division by zero
            return (features - median) / iqr
        
        else:
            raise ValueError(f"Unknown normalization method: {method}")
    
    @staticmethod
    def handle_missing_values(
        features: np.ndarray, 
        strategy: str = 'mean'
    ) -> np.ndarray:
        """
        Handle missing values in feature matrix
        
        Args:
            features: Feature matrix
            strategy: Imputation strategy ('mean', 'median', 'zero', or 'most_frequent')
            
        Returns:
            Features with missing values handled
        """
        if strategy == 'mean':
            col_means = np.nanmean(features, axis=0)
            col_means = np.nan_to_num(col_means, nan=0.0)
            return np.where(np.isnan(features), col_means, features)
        
        elif strategy == 'median':
            col_medians = np.nanmedian(features, axis=0)
            col_medians = np.nan_to_num(col_medians, nan=0.0)
            return np.where(np.isnan(features), col_medians, features)
        
        elif strategy == 'zero':
            return np.nan_to_num(features, nan=0.0)
        
        else:
            raise ValueError(f"Unknown imputation strategy: {strategy}")
    
    @staticmethod
    def select_k_best(
        features: np.ndarray, 
        labels: np.ndarray, 
        k: int = 10
    ) -> np.ndarray:
        """
        Select top k features using ANOVA F-value
        """
        try:
            from sklearn.feature_selection import f_classif
            f_scores, p_values = f_classif(features, labels)
            indices = np.argsort(f_scores)[::-1][:k]
            return indices
        except ImportError:
            return np.arange(min(k, features.shape[1] if len(features.shape) > 1 else k))

