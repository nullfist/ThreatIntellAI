from app.models.ioc_model import RiskLevel, ThreatLabel
from typing import List, Dict, Any
import random

class RiskClassifier:
    @staticmethod
    def classify_risk(threat_labels: List[ThreatLabel], confidence: float) -> RiskLevel:
        """Classify risk based on threat labels and confidence score"""
        malicious_labels = {ThreatLabel.MALWARE, ThreatLabel.PHISHING, ThreatLabel.C2, ThreatLabel.BOTNET}
        
        # Check if any malicious labels are present
        has_malicious = any(label in malicious_labels for label in threat_labels)
        
        if has_malicious and confidence > 0.7:
            return RiskLevel.MALICIOUS
        elif has_malicious and confidence > 0.4:
            return RiskLevel.SUSPICIOUS
        elif ThreatLabel.SCAM in threat_labels and confidence > 0.5:
            return RiskLevel.SUSPICIOUS
        else:
            return RiskLevel.SAFE

    @staticmethod
    def calculate_confidence(threat_data: Dict[str, Any]) -> float:
        """Calculate confidence score based on threat intelligence data"""
        base_confidence = 0.0
        
        # Simulate confidence calculation based on various factors
        if threat_data.get("reputation", 0) < 0:
            base_confidence += 0.3
        if threat_data.get("threat_count", 0) > 0:
            base_confidence += 0.4
        if threat_data.get("malicious_votes", 0) > threat_data.get("harmless_votes", 0):
            base_confidence += 0.3
            
        return min(base_confidence + random.uniform(0, 0.2), 1.0)