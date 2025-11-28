import os
from dotenv import load_dotenv

load_dotenv()

class APIConfig:
    """Configuration for external threat intelligence APIs"""
    
    # VirusTotal API
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
    
    # AbuseIPDB API  
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
    ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    # Optional: IBM X-Force, AlienVault OTX, etc.
    IBM_XFORCE_API_KEY = os.getenv("IBM_XFORCE_API_KEY", "")
    IBM_XFORCE_BASE_URL = "https://api.xforce.ibmcloud.com"
    
    # Rate limiting
    RATE_LIMIT_DELAY = 1.0  # seconds between API calls
    
    @classmethod
    def is_virustotal_configured(cls):
        return bool(cls.VIRUSTOTAL_API_KEY)
    
    @classmethod
    def is_abuseipdb_configured(cls):
        return bool(cls.ABUSEIPDB_API_KEY)