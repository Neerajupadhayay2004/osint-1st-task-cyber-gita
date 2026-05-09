import google.generativeai as genai
from app.core.config import settings
import logging
import json

logger = logging.getLogger(__name__)

class GeminiService:
    def __init__(self):
        if settings.GEMINI_API_KEY:
            genai.configure(api_key=settings.GEMINI_API_KEY)
            self.model = genai.GenerativeModel('gemini-1.5-flash')
        else:
            self.model = None
            logger.warning("GEMINI_API_KEY not configured")

    async def analyze_threat(self, threat_data: dict):
        """Uses Gemini AI to provide a detailed cybersecurity analysis of the gathered OSINT data."""
        if not self.model:
            return {"error": "Gemini AI not configured"}

        prompt = f"""
        You are a Senior Cyber Security Analyst. Analyze the following OSINT data and provide a professional threat report.
        
        DATA:
        {json.dumps(threat_data, indent=2)}
        
        Provide the report in the following JSON format:
        {{
            "summary": "Short summary of findings",
            "risk_assessment": "Detailed assessment of the risks",
            "recommendations": ["List of actionable steps"],
            "confidence_score": 0.95
        }}
        
        Ensure you only return valid JSON.
        """

        try:
            response = self.model.generate_content(prompt)
            # Try to extract JSON from response
            text = response.text
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0].strip()
            elif "```" in text:
                text = text.split("```")[1].split("```")[0].strip()
            
            return json.loads(text)
        except Exception as e:
            logger.error(f"Gemini AI Error: {e}")
            return {"error": f"AI Analysis failed: {str(e)}"}

gemini_service = GeminiService()
