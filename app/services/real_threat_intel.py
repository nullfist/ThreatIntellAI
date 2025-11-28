import requests
import time
from typing import Dict, Any, List, Optional
import json
from ..config.api_config import APIConfig

class RealThreatIntelligence:
    """Real threat intelligence service using external APIs"""
    
    def __init__(self):
        self.session = requests.Session()
        self.setup_headers()
    
    def setup_headers(self):
        """Setup API headers for different services"""
        self.virustotal_headers = {
            "x-apikey": APIConfig.VIRUSTOTAL_API_KEY,
            "Accept": "application/json"
        }
        
        self.abuseipdb_headers = {
            "Key": APIConfig.ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
    
    async def lookup_ip_real(self, ip: str) -> Dict[str, Any]:
        """Real IP lookup using multiple threat intelligence APIs"""
        results = {
            "ip": ip,
            "sources_checked": [],
            "reputation": 0,
            "threat_count": 0,
            "categories": [],
            "threat_names": [],
            "malicious_votes": 0,
            "harmless_votes": 0,
            "country": "Unknown",
            "last_reported": None
        }
        
        # VirusTotal IP Analysis
        vt_data = await self._virustotal_ip_lookup(ip)
        if vt_data:
            results["sources_checked"].append("VirusTotal")
            results.update(vt_data)
        
        # AbuseIPDB Analysis
        abuse_data = await self._abuseipdb_lookup(ip)
        if abuse_data:
            results["sources_checked"].append("AbuseIPDB")
            results.update(abuse_data)
        
        # Rate limiting between API calls
        time.sleep(APIConfig.RATE_LIMIT_DELAY)
        
        return results
    
    async def lookup_domain_real(self, domain: str) -> Dict[str, Any]:
        """Real domain lookup using threat intelligence APIs"""
        results = {
            "domain": domain,
            "sources_checked": [],
            "reputation": 0,
            "categories": [],
            "threat_names": [],
            "malicious_votes": 0,
            "harmless_votes": 0,
            "last_analysis_date": None
        }
        
        # VirusTotal Domain Analysis
        vt_data = await self._virustotal_domain_lookup(domain)
        if vt_data:
            results["sources_checked"].append("VirusTotal")
            results.update(vt_data)
        
        return results
    
    async def lookup_url_real(self, url: str) -> Dict[str, Any]:
        """Real URL lookup using threat intelligence APIs"""
        results = {
            "url": url,
            "sources_checked": [],
            "reputation": 0,
            "categories": [],
            "threat_names": [],
            "malicious_votes": 0,
            "harmless_votes": 0,
            "last_analysis_date": None
        }
        
        # VirusTotal URL Analysis
        vt_data = await self._virustotal_url_lookup(url)
        if vt_data:
            results["sources_checked"].append("VirusTotal")
            results.update(vt_data)
        
        return results
    
    async def lookup_hash_real(self, file_hash: str) -> Dict[str, Any]:
        """Real file hash lookup using threat intelligence APIs"""
        results = {
            "hash": file_hash,
            "sources_checked": [],
            "reputation": -1,  # Default suspicious for hashes
            "categories": [],
            "threat_names": [],
            "malicious_votes": 0,
            "harmless_votes": 0,
            "detection_rate": "0%",
            "last_analysis_date": None
        }
        
        # VirusTotal File Analysis
        vt_data = await self._virustotal_file_lookup(file_hash)
        if vt_data:
            results["sources_checked"].append("VirusTotal")
            results.update(vt_data)
        
        return results
    
    async def _virustotal_ip_lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        """VirusTotal IP address analysis"""
        if not APIConfig.is_virustotal_configured():
            return None
        
        try:
            url = f"{APIConfig.VIRUSTOTAL_BASE_URL}/ip_addresses/{ip}"
            response = self.session.get(url, headers=self.virustotal_headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                
                last_analysis_stats = attributes.get("last_analysis_stats", {})
                reputation = attributes.get("reputation", 0)
                country = attributes.get("country", "Unknown")
                
                # Extract categories from analysis results
                categories = []
                last_analysis_results = attributes.get("last_analysis_results", {})
                for engine, result in last_analysis_results.items():
                    category = result.get("category")
                    if category and category not in categories:
                        categories.append(category)
                
                return {
                    "reputation": reputation,
                    "threat_count": last_analysis_stats.get("malicious", 0),
                    "categories": categories[:5],  # Top 5 categories
                    "malicious_votes": last_analysis_stats.get("malicious", 0),
                    "harmless_votes": last_analysis_stats.get("harmless", 0),
                    "country": country,
                    "last_reported": attributes.get("last_analysis_date")
                }
            
        except Exception as e:
            print(f"VirusTotal IP lookup error: {e}")
        
        return None
    
    async def _abuseipdb_lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        """AbuseIPDB IP address analysis"""
        if not APIConfig.is_abuseipdb_configured():
            return None
        
        try:
            url = f"{APIConfig.ABUSEIPDB_BASE_URL}/check"
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90
            }
            
            response = self.session.get(url, headers=self.abuseipdb_headers, 
                                      params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                abuse_data = data.get("data", {})
                
                abuse_confidence = abuse_data.get("abuseConfidenceScore", 0)
                total_reports = abuse_data.get("totalReports", 0)
                country = abuse_data.get("countryCode", "Unknown")
                
                # Convert AbuseIPDB score to reputation (-100 to 100 scale)
                reputation = 100 - abuse_confidence
                
                return {
                    "reputation": reputation,
                    "threat_count": total_reports,
                    "categories": ["reported_abuse"] if total_reports > 0 else [],
                    "malicious_votes": total_reports,
                    "country": country,
                    "last_reported": abuse_data.get("lastReportedAt")
                }
            
        except Exception as e:
            print(f"AbuseIPDB lookup error: {e}")
        
        return None
    
    async def _virustotal_domain_lookup(self, domain: str) -> Optional[Dict[str, Any]]:
        """VirusTotal domain analysis"""
        if not APIConfig.is_virustotal_configured():
            return None
        
        try:
            url = f"{APIConfig.VIRUSTOTAL_BASE_URL}/domains/{domain}"
            response = self.session.get(url, headers=self.virustotal_headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                
                last_analysis_stats = attributes.get("last_analysis_stats", {})
                reputation = attributes.get("reputation", 0)
                
                # Extract categories and threat names
                categories = []
                threat_names = []
                
                last_analysis_results = attributes.get("last_analysis_results", {})
                for engine, result in last_analysis_results.items():
                    category = result.get("category")
                    if category and category not in categories:
                        categories.append(category)
                    
                    result_name = result.get("result")
                    if result_name and "malicious" in result_name.lower():
                        threat_names.append(result_name)
                
                return {
                    "reputation": reputation,
                    "threat_count": last_analysis_stats.get("malicious", 0),
                    "categories": categories[:5],
                    "threat_names": threat_names[:3],
                    "malicious_votes": last_analysis_stats.get("malicious", 0),
                    "harmless_votes": last_analysis_stats.get("harmless", 0),
                    "last_analysis_date": attributes.get("last_analysis_date")
                }
            
        except Exception as e:
            print(f"VirusTotal domain lookup error: {e}")
        
        return None
    
    async def _virustotal_url_lookup(self, url: str) -> Optional[Dict[str, Any]]:
        """VirusTotal URL analysis"""
        if not APIConfig.is_virustotal_configured():
            return None
        
        try:
            # URL needs to be base64 encoded without padding
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            url = f"{APIConfig.VIRUSTOTAL_BASE_URL}/urls/{url_id}"
            response = self.session.get(url, headers=self.virustotal_headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                
                last_analysis_stats = attributes.get("last_analysis_stats", {})
                
                # Extract categories
                categories = []
                last_analysis_results = attributes.get("last_analysis_results", {})
                for engine, result in last_analysis_results.items():
                    category = result.get("category")
                    if category and category not in categories:
                        categories.append(category)
                
                return {
                    "reputation": -last_analysis_stats.get("malicious", 0) * 10,
                    "threat_count": last_analysis_stats.get("malicious", 0),
                    "categories": categories[:5],
                    "malicious_votes": last_analysis_stats.get("malicious", 0),
                    "harmless_votes": last_analysis_stats.get("harmless", 0),
                    "last_analysis_date": attributes.get("last_analysis_date")
                }
            
        except Exception as e:
            print(f"VirusTotal URL lookup error: {e}")
        
        return None
    
    async def _virustotal_file_lookup(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """VirusTotal file hash analysis"""
        if not APIConfig.is_virustotal_configured():
            return None
        
        try:
            url = f"{APIConfig.VIRUSTOTAL_BASE_URL}/files/{file_hash}"
            response = self.session.get(url, headers=self.virustotal_headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                
                last_analysis_stats = attributes.get("last_analysis_stats", {})
                reputation = attributes.get("reputation", 0)
                
                # Extract threat names and categories
                categories = []
                threat_names = []
                
                last_analysis_results = attributes.get("last_analysis_results", {})
                for engine, result in last_analysis_results.items():
                    category = result.get("category")
                    if category and category not in categories:
                        categories.append(category)
                    
                    result_name = result.get("result")
                    if result_name and "malicious" in category.lower():
                        threat_names.append(result_name)
                
                total_engines = sum(last_analysis_stats.values())
                malicious_count = last_analysis_stats.get("malicious", 0)
                detection_rate = f"{(malicious_count / total_engines * 100):.1f}%" if total_engines > 0 else "0%"
                
                return {
                    "reputation": reputation,
                    "threat_count": malicious_count,
                    "categories": categories[:5],
                    "threat_names": threat_names[:3],
                    "malicious_votes": malicious_count,
                    "harmless_votes": last_analysis_stats.get("harmless", 0),
                    "detection_rate": detection_rate,
                    "last_analysis_date": attributes.get("last_analysis_date")
                }
            
        except Exception as e:
            print(f"VirusTotal file lookup error: {e}")
        
        return None