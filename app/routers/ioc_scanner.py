from fastapi import APIRouter, HTTPException
from typing import List
import json
import os
from datetime import datetime

# Fixed import paths - use relative imports
from ..models.ioc_model import IOCScanRequest, ScanResponse, IOCTypes
from ..services.threat_lookup import ThreatLookupService
from ..utils.risk_classifier import RiskClassifier
from ..utils.threat_labeler import ThreatLabeler
from ..services.ai_explainer import AIExplainService

router = APIRouter()

# Storage file path - fixed path
STORAGE_FILE = os.path.join(os.path.dirname(__file__), "..", "storage", "temp_results.json")

def load_scan_results() -> List[dict]:
    """Load previous scan results from JSON storage"""
    try:
        if os.path.exists(STORAGE_FILE):
            with open(STORAGE_FILE, 'r') as f:
                return json.load(f)
    except Exception:
        pass
    return []

def save_scan_result(result: dict):
    """Save scan result to JSON storage"""
    try:
        results = load_scan_results()
        results.append(result)
        
        # Keep only last 100 results to prevent file from growing too large
        if len(results) > 100:
            results = results[-100:]
            
        # Ensure storage directory exists
        os.makedirs(os.path.dirname(STORAGE_FILE), exist_ok=True)
            
        with open(STORAGE_FILE, 'w') as f:
            json.dump(results, f, indent=2)
    except Exception as e:
        print(f"Warning: Could not save result: {e}")

@router.post("/scan", response_model=ScanResponse)
async def scan_ioc(scan_request: IOCScanRequest):
    """
    Scan an Indicator of Compromise (IOC) for threats
    
    Supported IOC types: ip, url, domain, hash
    """
    try:
        # Validate IOC
        if not ThreatLookupService.validate_ioc(scan_request.value, scan_request.type):
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid {scan_request.type.value}: {scan_request.value}"
            )
        
        # Perform threat lookup based on IOC type
        threat_data = {}
        if scan_request.type == IOCTypes.IP:
            threat_data = ThreatLookupService.lookup_ip(scan_request.value)
        elif scan_request.type == IOCTypes.URL:
            threat_data = ThreatLookupService.lookup_url(scan_request.value)
        elif scan_request.type == IOCTypes.DOMAIN:
            threat_data = ThreatLookupService.lookup_domain(scan_request.value)
        elif scan_request.type == IOCTypes.HASH:
            threat_data = ThreatLookupService.lookup_hash(scan_request.value)
        
        # Analyze threat data
        threat_labels = ThreatLabeler.detect_threat_labels(threat_data)
        confidence_score = RiskClassifier.calculate_confidence(threat_data)
        risk_level = RiskClassifier.classify_risk(threat_labels, confidence_score)
        
        # Generate AI explanation
        ai_explanation = AIExplainService.generate_explanation(
            scan_request.value, 
            scan_request.type, 
            risk_level, 
            threat_labels, 
            threat_data
        )
        
        # Generate recommended actions
        recommended_actions = AIExplainService.generate_recommended_actions(
            risk_level, 
            threat_labels
        )
        
        # Build response
        response_data = {
            "ioc": scan_request.value,
            "ioc_type": scan_request.type.value,
            "risk_level": risk_level,
            "threat_labels": threat_labels,
            "confidence_score": round(confidence_score, 2),
            "technical_details": threat_data,
            "ai_explanation": ai_explanation,
            "recommended_actions": recommended_actions,
            "timestamp": datetime.now().isoformat(),
            "sources_checked": threat_data.get("sources", [])
        }
        
        # Save result to storage
        save_scan_result(response_data)
        
        return ScanResponse(**response_data)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@router.get("/scan-history")
async def get_scan_history(limit: int = 10):
    """Get recent scan history"""
    results = load_scan_results()
    return {"scans": results[-limit:], "total_count": len(results)}