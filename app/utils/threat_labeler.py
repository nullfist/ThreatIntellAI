from app.models.ioc_model import ThreatLabel
from typing import List, Dict, Any
import random

class ThreatLabeler:
    @staticmethod
    def detect_threat_labels(threat_data: Dict[str, Any]) -> List[ThreatLabel]:
        """Detect threat labels based on threat intelligence data"""
        labels = []
        
        # Simulate threat detection logic
        reputation = threat_data.get("reputation", 0)
        categories = threat_data.get("categories", [])
        threat_names = threat_data.get("threat_names", [])
        
        # Basic rule-based labeling
        if reputation < -1:
            labels.append(ThreatLabel.MALICIOUS)
        
        # Category-based labeling
        for category in categories:
            category_lower = category.lower()
            if any(term in category_lower for term in ['malware', 'trojan', 'virus']):
                labels.append(ThreatLabel.MALWARE)
            elif 'phishing' in category_lower:
                labels.append(ThreatLabel.PHISHING)
            elif any(term in category_lower for term in ['c2', 'command', 'control']):
                labels.append(ThreatLabel.C2)
            elif 'botnet' in category_lower:
                labels.append(ThreatLabel.BOTNET)
            elif 'scam' in category_lower:
                labels.append(ThreatLabel.SCAM)
        
        # Threat name analysis
        for threat in threat_names:
            threat_lower = threat.lower()
            if any(term in threat_lower for term in ['phish', 'credential']):
                labels.append(ThreatLabel.PHISHING)
            elif any(term in threat_lower for term in ['botnet', 'bot']):
                labels.append(ThreatLabel.BOTNET)
        
        # Remove duplicates and ensure at least one label
        unique_labels = list(set(labels))
        if not unique_labels and reputation >= 0:
            unique_labels.append(ThreatLabel.CLEAN)
        elif not unique_labels:
            unique_labels.append(ThreatLabel.SUSPICIOUS)
            
        return unique_labels