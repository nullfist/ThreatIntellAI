from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum

class IOCTypes(str, Enum):
    IP = "ip"
    URL = "url"
    DOMAIN = "domain"
    HASH = "hash"

class RiskLevel(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"

class ThreatLabel(str, Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    C2 = "c2"
    BOTNET = "botnet"
    SCAM = "scam"
    CLEAN = "clean"

# Updated to match the expected API schema
class IOCScanRequest(BaseModel):
    value: str = Field(..., description="Indicator of Compromise to scan")
    type: IOCTypes = Field(..., description="Type of IOC")

class ScanResponse(BaseModel):
    ioc: str
    ioc_type: str
    risk_level: RiskLevel
    threat_labels: List[ThreatLabel]
    confidence_score: float = Field(..., ge=0, le=1)
    technical_details: Optional[Dict[str, Any]] = {}
    ai_explanation: str
    recommended_actions: List[str]
    timestamp: str
    sources_checked: List[str]

# For AI explanation endpoint
class AIExplainRequest(BaseModel):
    context: str
    ioc_id: str
    detail_level: str = "concise"