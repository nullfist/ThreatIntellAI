from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum

class LogType(str, Enum):
    AUTH_LOG = "auth_log"
    IIS = "iis"
    FIREWALL = "firewall"
    WINDOWS_EVENT = "windows_event"
    APACHE = "apache"

class ThreatSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class LogAnalysisRequest(BaseModel):
    log_type: LogType
    description: Optional[str] = "Manual log upload"

class LogAnalysisResponse(BaseModel):
    analysis_id: str
    log_type: LogType
    threat_severity: str
    suspicious_patterns: List[str]
    source_ips: List[str]
    failed_logins: int
    brute_force_attempts: int
    unknown_users: List[str]
    ai_explanation: str
    recommended_actions: List[str]
    summary: str
    timestamp: str
    analysis_duration: float

class PatternDetection(BaseModel):
    pattern_name: str
    description: str
    severity: ThreatSeverity
    occurrences: int
    examples: List[str]