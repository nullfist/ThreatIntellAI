from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime

class ReportFormat(str, Enum):
    PDF = "pdf"
    HTML = "html"
    BOTH = "both"

class ReportType(str, Enum):
    INCIDENT = "incident"
    SECURITY_SCAN = "security_scan"
    LOG_ANALYSIS = "log_analysis"
    COMPREHENSIVE = "comprehensive"

class SchoolInfo(BaseModel):
    school_name: str = Field(..., description="Name of the school")
    district: Optional[str] = None
    contact_person: Optional[str] = None
    contact_email: Optional[str] = None
    phone: Optional[str] = None

class StudentInfo(BaseModel):
    student_name: Optional[str] = None
    grade_level: Optional[str] = None
    teacher_name: Optional[str] = None
    incident_location: Optional[str] = None

class ReportRequest(BaseModel):
    report_type: ReportType
    format: ReportFormat = ReportFormat.PDF
    title: str = Field(..., description="Report title")
    school_info: SchoolInfo
    student_info: Optional[StudentInfo] = None
    ioc_analysis_ids: Optional[List[str]] = []
    log_analysis_ids: Optional[List[str]] = []
    custom_context: Optional[str] = None
    include_timeline: bool = True
    include_recommendations: bool = True

class ReportResponse(BaseModel):
    report_id: str
    report_type: ReportType
    format: ReportFormat
    title: str
    download_url: str
    file_path: str
    file_size: int
    generated_at: str
    school_name: str