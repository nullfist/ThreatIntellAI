import requests
from typing import Dict, Any, List
import random
from ..models.ioc_model import IOCTypes  # Fixed import
import time

class ThreatLookupService:
    """
    Simulates threat intelligence lookups using public APIs
    In production, replace with actual API calls to VirusTotal, AbuseIPDB, etc.
    """
    
    @staticmethod
    def validate_ioc(ioc: str, ioc_type: IOCTypes) -> bool:
        """Basic IOC validation"""
        if ioc_type == IOCTypes.IP:
            import re
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            return bool(re.match(ip_pattern, ioc))
        elif ioc_type == IOCTypes.DOMAIN:
            return '.' in ioc and len(ioc) > 3
        elif ioc_type == IOCTypes.URL:
            return ioc.startswith(('http://', 'https://'))
        elif ioc_type == IOCTypes.HASH:
            return len(ioc) in [32, 40, 64]  # MD5, SHA1, SHA256
        return False
    
    @staticmethod
    def lookup_ip(ip: str) -> Dict[str, Any]:
        """Simulate IP threat lookup"""
        # Simulate API call delay
        time.sleep(0.1)  # Reduced for faster testing
        
        # Mock threat data - in production, call actual APIs
        return {
            "ip": ip,
            "reputation": random.randint(-3, 1),
            "country": random.choice(["US", "CN", "RU", "DE", "FR", "Unknown"]),
            "threat_count": random.randint(0, 5),
            "categories": random.sample(["malware", "botnet", "phishing", "c2"], random.randint(0, 2)),
            "threat_names": random.sample(["Generic Malware", "Phishing Kit", "C2 Server"], random.randint(0, 2)),
            "malicious_votes": random.randint(0, 10),
            "harmless_votes": random.randint(0, 15),
            "sources": ["VirusTotal", "AbuseIPDB", "ThreatFox"]
        }
    
    @staticmethod
    def lookup_domain(domain: str) -> Dict[str, Any]:
        """Simulate domain threat lookup"""
        time.sleep(0.1)
        
        return {
            "domain": domain,
            "reputation": random.randint(-2, 1),
            "categories": random.sample(["phishing", "malware", "scam", "suspicious"], random.randint(0, 2)),
            "threat_names": random.sample(["Phishing Domain", "Malware Distribution"], random.randint(0, 2)),
            "malicious_votes": random.randint(0, 8),
            "harmless_votes": random.randint(0, 12),
            "sources": ["VirusTotal", "Google Safe Browsing"]
        }
    
    @staticmethod
    def lookup_url(url: str) -> Dict[str, Any]:
        """Simulate URL threat lookup"""
        time.sleep(0.1)
        
        return {
            "url": url,
            "reputation": random.randint(-3, 1),
            "categories": random.sample(["phishing", "malware", "scam", "suspicious"], random.randint(0, 3)),
            "threat_names": random.sample(["Phishing Page", "Malware Download", "Scam Site"], random.randint(0, 2)),
            "malicious_votes": random.randint(0, 15),
            "harmless_votes": random.randint(0, 10),
            "sources": ["VirusTotal", "URLScan.io"]
        }
    
    @staticmethod
    def lookup_hash(file_hash: str) -> Dict[str, Any]:
        """Simulate file hash threat lookup"""
        time.sleep(0.1)
        
        return {
            "hash": file_hash,
            "reputation": random.randint(-3, 0),
            "categories": random.sample(["trojan", "ransomware", "worm", "adware"], random.randint(0, 2)),
            "threat_names": random.sample(["Trojan.Generic", "Ransomware.LockBit", "Worm.Sality"], random.randint(0, 2)),
            "malicious_votes": random.randint(0, 20),
            "harmless_votes": random.randint(0, 5),
            "detection_rate": f"{random.randint(0, 100)}%",
            "sources": ["VirusTotal", "MalwareBazaar"]
        }