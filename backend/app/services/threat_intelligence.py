import httpx
import logging

from typing import List, Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class ThreatIntelligenceService:

    def __init__(self):

        self.client = httpx.AsyncClient(timeout=15.0)

    # ---------------------------------------------------
    # Latest CVEs
    # ---------------------------------------------------

    async def get_latest_cves(self):

        try:

            response = await self.client.get(
                "https://cve.circl.lu/api/last"
            )

            if response.status_code == 200:

                return response.json()[:20]

            return []

        except Exception as e:

            logger.error(f"CVE fetch error: {e}")

            return []

    # ---------------------------------------------------
    # Search CVEs
    # ---------------------------------------------------

    async def search_cves(self, query: str):
<<<<<<< HEAD
        try:
            query = query.strip()
            if not query:
                return []

            # 1. Try search by CVE ID
            if query.upper().startswith("CVE-"):
                try:
                    response = await self.client.get(f"https://cve.circl.lu/api/cve/{query.upper()}")
                    if response.status_code == 200:
                        data = response.json()
                        return [data] if data else []
                except:
                    pass

            # 2. Try general search
            response = await self.client.get(f"https://cve.circl.lu/api/search/{query}")
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict):
                    return data.get("results", [])
                elif isinstance(data, list):
                    return data
            
            # 3. Fallback to NVD if CIRCL is failing (optional but good)
            # For now, let's just return empty if CIRCL fails
=======

        try:

            query = query.strip()

            if query.upper().startswith("CVE-"):

                response = await self.client.get(
                    f"https://cve.circl.lu/api/cve/{query.upper()}"
                )

                if response.status_code == 200:

                    data = response.json()

                    return [data]

            response = await self.client.get(
                f"https://cve.circl.lu/api/search/{query}"
            )

            if response.status_code == 200:

                data = response.json()

                if isinstance(data, dict):

                    return data.get("results", [])

                elif isinstance(data, list):

                    return data

>>>>>>> d0f073da67d0618f343f8ec0c7a223c3526914d5
            return []

        except Exception as e:

            logger.error(f"CVE search error: {e}")

            return []

    # ---------------------------------------------------
    # Malware Feed
    # ---------------------------------------------------

    async def get_malware_feeds(self):

        try:

            response = await self.client.get(
                "https://urlhaus-api.abuse.ch/v1/urls/recent/"
            )

            if response.status_code == 200:

                data = response.json()

                return data.get("urls", [])[:20]

            return []

        except Exception as e:

            logger.error(f"Malware feed error: {e}")

            return []

    # ---------------------------------------------------
    # Email Breach Intelligence
    # ---------------------------------------------------

    async def search_breaches(self, email: str):

        try:

            email = email.strip().lower()

            domain = (
                email.split("@")[-1]
                if "@" in email
                else ""
            )

            breach_data = {
                "breached": False,
                "breaches": []
            }

            # ---------------------------------------------------
            # XposedOrNot
            # ---------------------------------------------------

            try:

                response = await self.client.get(
                    f"https://api.xposedornot.com/v1/check-email?email={email}"
                )

                if response.status_code == 200:

                    data = response.json()

                    breach_data = {
                        "breached": True,
                        "breaches": data
                    }

                elif response.status_code == 404:

                    breach_data = {
                        "breached": False,
                        "message": "No breaches found"
                    }

            except Exception as e:

                logger.warning(f"XposedOrNot failed: {e}")

            # ---------------------------------------------------
            # Domain Analysis
            # ---------------------------------------------------

            disposable_domains = [
                "tempmail.com",
                "mailinator.com",
                "guerrillamail.com",
                "10minutemail.com"
            ]

            common_domains = [
                "gmail.com",
                "yahoo.com",
                "outlook.com",
                "hotmail.com",
                "protonmail.com"
            ]

            domain_info = {
                "domain": domain,
                "is_disposable": domain in disposable_domains,
                "provider":
                    "Common Provider"
                    if domain in common_domains
                    else "Private / Custom"
            }

            # ---------------------------------------------------
            # AI Risk Score
            # ---------------------------------------------------

            risk_score = 10

            if breach_data["breached"]:
                risk_score += 60

            if domain_info["is_disposable"]:
                risk_score += 25

            # ---------------------------------------------------
            # FINAL RESPONSE
            # ---------------------------------------------------

            return {
                "email": email,
                "domain_info": domain_info,
                "breach_info": breach_data,
                "risk_score": risk_score,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:

            logger.error(f"Error in search_breaches: {e}")

            return {
                "email": email,
                "error": str(e)
            }

# ---------------------------------------------------
# Singleton
# ---------------------------------------------------

threat_intel_service = ThreatIntelligenceService()