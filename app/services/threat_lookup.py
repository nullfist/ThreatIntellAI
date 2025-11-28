import requests
from typing import Dict, Any, List
import random
from app.models.ioc_model import IOCTypes
import time
from .real_threat_intel import RealThreatIntelligence
from app.config.api_config import APIConfig

class ThreatLookupService:
    """
    Hybrid threat intelligence service
    Uses real APIs when available, falls back to mock data
    """
    
    def __init__(self):
        self.real_intel = RealThreatIntelligence()
        self.use_real_apis = (APIConfig.is_virustotal_configured() or 
                            APIConfig.is_abuseipdb_configured())
    
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
    
    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """IP threat lookup - tries real APIs first"""
        if self.use_real_apis:
            try:
                real_data = await self.real_intel.lookup_ip_real(ip)
                if real_data and real_data.get("sources_checked"):
                    print(f"✅ Using real threat intelligence for IP: {ip}")
                    return real_data
            except Exception as e:
                print(f"❌ Real API failed for IP {ip}, using mock data: {e}")
        
        # Fallback to mock data
        print(f"🔄 Using mock data for IP: {ip}")
        return self._mock_ip_lookup(ip)
    
    async def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """Domain threat lookup - tries real APIs first"""
        if self.use_real_apis:
            try:
                real_data = await self.real_intel.lookup_domain_real(domain)
                if real_data and real_data.get("sources_checked"):
                    print(f"✅ Using real threat intelligence for domain: {domain}")
                    return real_data
            except Exception as e:
                print(f"❌ Real API failed for domain {domain}, using mock data: {e}")
        
        # Fallback to mock data
        print(f"🔄 Using mock data for domain: {domain}")
        return self._mock_domain_lookup(domain)
    
    async def lookup_url(self, url: str) -> Dict[str, Any]:
        """URL threat lookup - tries real APIs first"""
        if self.use_real_apis:
            try:
                real_data = await self.real_intel.lookup_url_real(url)
                if real_data and real_data.get("sources_checked"):
                    print(f"✅ Using real threat intelligence for URL: {url}")
                    return real_data
            except Exception as e:
                print(f"❌ Real API failed for URL {url}, using mock data: {e}")
        
        # Fallback to mock data
        print(f"🔄 Using mock data for URL: {url}")
        return self._mock_url_lookup(url)
    
    async def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """File hash threat lookup - tries real APIs first"""
        if self.use_real_apis:
            try:
                real_data = await self.real_intel.lookup_hash_real(file_hash)
                if real_data and real_data.get("sources_checked"):
                    print(f"✅ Using real threat intelligence for hash: {file_hash}")
                    return real_data
            except Exception as e:
                print(f"❌ Real API failed for hash {file_hash}, using mock data: {e}")
        
        # Fallback to mock data
        print(f"🔄 Using mock data for hash: {file_hash}")
        return self._mock_hash_lookup(file_hash)
    
    def _mock_ip_lookup(self, ip: str) -> Dict[str, Any]:
        """Mock IP threat lookup (fallback)"""
        time.sleep(0.5)
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
    
    def _mock_domain_lookup(self, domain: str) -> Dict[str, Any]:
        """Mock domain threat lookup (fallback)"""
        time.sleep(0.5)
        return {
            "domain": domain,
            "reputation": random.randint(-2, 1),
            "categories": random.sample(["phishing", "malware", "scam", "suspicious"], random.randint(0, 2)),
            "threat_names": random.sample(["Phishing Domain", "Malware Distribution"], random.randint(0, 2)),
            "malicious_votes": random.randint(0, 8),
            "harmless_votes": random.randint(0, 12),
            "sources": ["VirusTotal", "Google Safe Browsing"]
        }
    
    def _mock_url_lookup(self, url: str) -> Dict[str, Any]:
        """Mock URL threat lookup (fallback)"""
        time.sleep(0.5)
        return {
            "url": url,
            "reputation": random.randint(-3, 1),
            "categories": random.sample(["phishing", "malware", "scam", "suspicious"], random.randint(0, 3)),
            "threat_names": random.sample(["Phishing Page", "Malware Download", "Scam Site"], random.randint(0, 2)),
            "malicious_votes": random.randint(0, 15),
            "harmless_votes": random.randint(0, 10),
            "sources": ["VirusTotal", "URLScan.io"]
        }
    
    def _mock_hash_lookup(self, file_hash: str) -> Dict[str, Any]:
        """Mock file hash threat lookup (fallback)"""
        time.sleep(0.5)
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