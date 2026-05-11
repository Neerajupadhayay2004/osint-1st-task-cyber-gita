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
            logger.warning("GEMINI_API_KEY not found in settings")

    async def analyze_threat(self, raw_data: dict) -> dict:
        """
        Uses Gemini to analyze raw OSINT data and provide a structured report.
        """
        if not self.model:
            return self._get_fallback_analysis(raw_data, "Gemini API key not configured")

        prompt = f"""
        Analyze the following OSINT data and provide a detailed security report in JSON format.
        The JSON should have the following structure:
        {{
            "summary": "A brief overview of the findings",
            "risk_assessment": "Detailed assessment of the threat level",
            "recommendations": ["list", "of", "actionable", "steps"],
            "technical_details": "Key technical observations"
        }}

        Raw OSINT Data:
        {json.dumps(raw_data, indent=2)}
        """

        try:
            response = self.model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    candidate_count=1,
                    temperature=0.3
                )
            )
            
            content = response.text.strip()
            if content.startswith("```json"):
                content = content.split("```json")[1].split("```")[0].strip()
            elif content.startswith("```"):
                content = content.split("```")[1].split("```")[0].strip()
            
            return json.loads(content)
        except Exception as e:
            logger.error(f"Gemini analysis error: {e}")
            return self._get_fallback_analysis(raw_data, str(e))

    def _get_fallback_analysis(self, raw_data: dict, error_msg: str) -> dict:
        """Rule-based analysis when AI fails."""
        shodan = raw_data.get("shodan", {})
        abuse = raw_data.get("abuseipdb", {})
        vt = raw_data.get("virustotal", {})
        
        # Simple heuristic
        malicious_votes = vt.get("malicious_votes", 0)
        abuse_score = abuse.get("abuse_score", 0)
        
        risk_level = "Low"
        if malicious_votes > 0 or abuse_score > 20:
            risk_level = "Medium"
        if malicious_votes > 5 or abuse_score > 50:
            risk_level = "High"
            
        summary = f"Automated analysis (AI Offline: {error_msg[:50]}...)"
        risk_assessment = f"Risk level is {risk_level} based on {malicious_votes} malicious detections and an abuse score of {abuse_score}."
        
        recommendations = ["Monitor network traffic", "Update firewall rules"]
        if risk_level != "Low":
            recommendations.append("Isolate affected system")
            recommendations.append("Perform deep scan")
            
        return {
            "summary": summary,
            "risk_assessment": risk_assessment,
            "recommendations": recommendations,
            "technical_details": f"Fallback triggered due to: {error_msg}"
        }

gemini_service = GeminiService()
