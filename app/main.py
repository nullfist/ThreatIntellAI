from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import uvicorn
import os

app = FastAPI(
    title="ThreatIntellAI",
    description="Automated Cyber Defense Platform",
    version="1.1.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure static directory exists
os.makedirs("app/static/css", exist_ok=True)
os.makedirs("app/static/js", exist_ok=True)

# Mount static files - FIXED PATH
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Import routers directly
from app.routers.ioc_scanner import router as ioc_router
from app.routers.ai_router import router as ai_router
from app.routers.log_analysis import router as log_router
from app.routers.report_generator import router as report_router
from app.routers.frontend import router as frontend_router

# Include routers
app.include_router(ioc_router, prefix="/api/v1/ioc", tags=["ioc"])
app.include_router(ai_router, prefix="/api/v1/ai", tags=["ai"])
app.include_router(log_router, prefix="/api/v1/logs", tags=["logs"])
app.include_router(report_router, prefix="/api/v1/report", tags=["reports"])
app.include_router(frontend_router, tags=["frontend"])

@app.get("/")
async def root():
    return {
        "message": "ThreatIntellAI Backend Running",
        "version": "1.1.0",
        "endpoints": {
            "dashboard": "/",
            "scan_ioc": "/upload/ioc",
            "analyze_logs": "/upload/logs", 
            "ai_explain": "/api/v1/ai/explain",
            "generate_report": "/api/v1/report/generate",
            "health": "/health"
        }
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "ThreatIntellAI"}

if __name__ == "__main__":
    print("🚀 ThreatIntellAI Server Starting on http://localhost:8080")
    print("📱 Frontend Dashboard: http://localhost:8080/")
    print("📁 Static files mounted at: /static/")
    uvicorn.run("app.main:app", host="0.0.0.0", port=8080, reload=True)