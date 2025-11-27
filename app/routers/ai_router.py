from fastapi import APIRouter
from ..models.ioc_model import AIExplainRequest
from ..services.ai_explainer import AIExplainService

router = APIRouter()

@router.get("/test")
async def test_ai():
    """Test if AI endpoint is working"""
    return {
        "message": "✅ AI endpoint is working!",
        "status": "operational",
        "endpoints": {
            "explain": "POST /api/v1/ai/explain",
            "capabilities": "GET /api/v1/ai/capabilities",
            "test": "GET /api/v1/ai/test"
        }
    }

@router.post("/explain")
async def explain_threat(explain_request: AIExplainRequest):
    """
    AI-powered threat analysis (Ready for custom model)
    """
    return AIExplainService.explain_threat_context(
        context=explain_request.context,
        ioc_id=explain_request.ioc_id,
        detail_level=explain_request.detail_level
    )

@router.get("/capabilities")
async def get_ai_capabilities():
    """
    Get AI system capabilities and integration points
    """
    return AIExplainService.get_ai_capabilities()