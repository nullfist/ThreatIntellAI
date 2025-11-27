from fastapi import APIRouter, Request, Form, File, UploadFile, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from typing import Optional
import json
import os
from datetime import datetime

from ..models.ioc_model import IOCScanRequest, IOCTypes
from ..models.log_model import LogType
from ..models.report_model import ReportRequest, ReportType, ReportFormat, SchoolInfo

router = APIRouter()

# Setup templates
templates = Jinja2Templates(directory="app/templates")

@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard page"""
    return templates.TemplateResponse("dashboard.html", {"request": request})

@router.get("/upload/ioc", response_class=HTMLResponse)
async def upload_ioc_page(request: Request):
    """IOC upload page"""
    return templates.TemplateResponse("upload_ioc.html", {
        "request": request,
        "ioc_types": [t.value for t in IOCTypes]
    })

@router.get("/upload/logs", response_class=HTMLResponse)
async def upload_logs_page(request: Request):
    """Logs upload page"""
    return templates.TemplateResponse("upload_logs.html", {
        "request": request,
        "log_types": [t.value for t in LogType]
    })

@router.get("/results", response_class=HTMLResponse)
async def results_page(request: Request):
    """Results display page"""
    return templates.TemplateResponse("results.html", {"request": request})

@router.get("/history", response_class=HTMLResponse)
async def history_page(request: Request):
    """Scan history page"""
    return templates.TemplateResponse("scan_history.html", {"request": request})

@router.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request):
    """Reports generation page"""
    return templates.TemplateResponse("reports.html", {"request": request})

# API integration endpoints for frontend - FIXED VERSION
@router.post("/api/scan-ioc")
async def scan_ioc_frontend(
    ioc_value: str = Form(...),
    ioc_type: str = Form(...)
):
    """Frontend endpoint for IOC scanning - FIXED"""
    try:
        # Import the actual scan function
        from app.routers.ioc_scanner import scan_ioc
        
        # Create scan request
        scan_request = IOCScanRequest(value=ioc_value, type=IOCTypes(ioc_type))
        
        # Call the scan function directly
        result = await scan_ioc(scan_request)
        
        return JSONResponse({
            "success": True,
            "result": result.dict(),
            "redirect_url": f"/results"
        })
    except Exception as e:
        return JSONResponse({
            "success": False,
            "error": str(e)
        })

@router.post("/api/upload-logs")
async def upload_logs_frontend(
    file: UploadFile = File(...),
    log_type: str = Form("auth_log")
):
    """Frontend endpoint for log upload - FIXED"""
    try:
        # Import the actual upload function
        from app.routers.log_analysis import upload_and_analyze_log
        
        # Call the upload function directly
        result = await upload_and_analyze_log(file, LogType(log_type))
        
        return JSONResponse({
            "success": True,
            "result": result.dict(),
            "redirect_url": f"/results"
        })
    except Exception as e:
        return JSONResponse({
            "success": False,
            "error": str(e)
        })

@router.post("/api/generate-report")
async def generate_report_frontend(
    title: str = Form(...),
    school_name: str = Form(...),
    report_type: str = Form("incident"),
    format: str = Form("pdf")
):
    """Frontend endpoint for report generation - FIXED"""
    try:
        # Import the actual report function
        from app.routers.report_generator import generate_report
        
        # Create report request
        report_request = ReportRequest(
            report_type=ReportType(report_type),
            format=ReportFormat(format),
            title=title,
            school_info=SchoolInfo(school_name=school_name)
        )
        
        # Call the report function directly
        result = await generate_report(report_request)
        
        return JSONResponse({
            "success": True,
            "result": result.dict(),
            "download_url": f"/api/v1/report/download/{result.report_id}?format={format}"
        })
    except Exception as e:
        return JSONResponse({
            "success": False,
            "error": str(e)
        })

@router.get("/api/scan-history")
async def get_scan_history_frontend():
    """Frontend endpoint for scan history - FIXED"""
    try:
        # Load from storage
        storage_file = "app/storage/temp_results.json"
        if os.path.exists(storage_file):
            with open(storage_file, 'r') as f:
                scans = json.load(f)
            return JSONResponse({"success": True, "scans": scans[-10:]})  # Last 10 scans
        else:
            return JSONResponse({"success": True, "scans": []})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)})

# Test endpoint to verify API is working
@router.get("/api/test")
async def test_api():
    """Test if API endpoints are working"""
    return JSONResponse({
        "status": "success",
        "message": "Frontend API endpoints are working!",
        "endpoints": {
            "scan_ioc": "POST /api/scan-ioc",
            "upload_logs": "POST /api/upload-logs", 
            "generate_report": "POST /api/generate-report",
            "scan_history": "GET /api/scan-history"
        }
    })