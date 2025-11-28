from fastapi import APIRouter, HTTPException
from typing import List
import json
import os
from datetime import datetime

from ..models.ioc_model import ScanRequest, ScanResponse, IOCTypes
from ..services.threat_lookup import ThreatLookupService
from ..utils.risk_classifier import RiskClassifier
from ..utils.threat_labeler import ThreatLabeler
from ..services.ai_explainer import AIExplainService

router = APIRouter()

# Initialize services
threat_lookup = ThreatLookupService()
STORAGE_FILE = "app/storage/temp_results.json"

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
async def scan_ioc(scan_request: ScanRequest):
    """
    Scan an Indicator of Compromise (IOC) for threats
    
    Supported IOC types: ip, url, domain, hash
    """
    try:
        print(f"🔍 Scanning IOC: {scan_request.value} (Type: {scan_request.type})")
        
        # Validate IOC
        if not ThreatLookupService.validate_ioc(scan_request.value, scan_request.type):
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid {scan_request.type.value}: {scan_request.value}"
            )
        
        # Perform threat lookup based on IOC type
        threat_data = {}
        if scan_request.type == IOCTypes.IP:
            print(f"🌐 Looking up IP: {scan_request.value}")
            threat_data = await threat_lookup.lookup_ip(scan_request.value)
        elif scan_request.type == IOCTypes.URL:
            print(f"🌐 Looking up URL: {scan_request.value}")
            threat_data = await threat_lookup.lookup_url(scan_request.value)
        elif scan_request.type == IOCTypes.DOMAIN:
            print(f"🌐 Looking up Domain: {scan_request.value}")
            threat_data = await threat_lookup.lookup_domain(scan_request.value)
        elif scan_request.type == IOCTypes.HASH:
            print(f"🌐 Looking up Hash: {scan_request.value}")
            threat_data = await threat_lookup.lookup_hash(scan_request.value)
        
        print(f"✅ Threat data received: {len(threat_data)} fields")
        
        # Analyze threat data
        threat_labels = ThreatLabeler.detect_threat_labels(threat_data)
        confidence_score = RiskClassifier.calculate_confidence(threat_data)
        risk_level = RiskClassifier.classify_risk(threat_labels, confidence_score)
        
        print(f"📊 Analysis - Risk: {risk_level}, Confidence: {confidence_score}, Threats: {threat_labels}")
        
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
            "sources_checked": threat_data.get("sources_checked", threat_data.get("sources", ["Mock Data"]))
        }
        
        # Save result to storage
        save_scan_result(response_data)
        
        print(f"🎉 Scan completed successfully for {scan_request.value}")
        
        return ScanResponse(**response_data)
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Scan failed for {scan_request.value}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@router.get("/scan-history")
async def get_scan_history(limit: int = 10):
    """Get recent scan history"""
    try:
        results = load_scan_results()
        return {
            "scans": results[-limit:], 
            "total_count": len(results),
            "message": f"Showing last {min(limit, len(results))} scans"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load scan history: {str(e)}")

@router.get("/test-scan")
async def test_scan():
    """Test endpoint to verify IOC scanner is working"""
    try:
        # Test with a safe domain
        test_request = ScanRequest(value="google.com", type=IOCTypes.DOMAIN)
        result = await scan_ioc(test_request)
        
        return {
            "status": "success",
            "message": "IOC Scanner is working correctly",
            "test_result": {
                "ioc": result.ioc,
                "risk_level": result.risk_level,
                "confidence": result.confidence_score,
                "threats_found": len(result.threat_labels)
            }
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"IOC Scanner test failed: {str(e)}"
        }

@router.get("/api-status")
async def get_api_status():
    """Check status of external threat intelligence APIs"""
    from ..config.api_config import APIConfig
    
    return {
        "real_apis_available": threat_lookup.use_real_apis,
        "virustotal_configured": APIConfig.is_virustotal_configured(),
        "abuseipdb_configured": APIConfig.is_abuseipdb_configured(),
        "status": "Using real APIs" if threat_lookup.use_real_apis else "Using mock data",
        "message": "Add API keys to .env file to enable real threat intelligence" if not threat_lookup.use_real_apis else "Real threat intelligence is active"
    }

@router.delete("/clear-history")
async def clear_scan_history():
    """Clear all scan history (for testing)"""
    try:
        if os.path.exists(STORAGE_FILE):
            os.remove(STORAGE_FILE)
        return {"message": "Scan history cleared successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear history: {str(e)}")

# Health check endpoint for this router
@router.get("/health")
async def health_check():
    """Health check for IOC scanner"""
    return {
        "status": "healthy",
        "service": "IOC Scanner",
        "timestamp": datetime.now().isoformat(),
        "features": {
            "ip_scanning": True,
            "url_scanning": True,
            "domain_scanning": True,
            "hash_scanning": True,
            "real_apis": threat_lookup.use_real_apis
        }
    }