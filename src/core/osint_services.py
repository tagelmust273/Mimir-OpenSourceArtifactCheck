"""OSINT services integration"""

import logging
from typing import Dict
from security.http_client import http_client
from config import settings

logger = logging.getLogger(__name__)


class OSINTServices:
    """Integration with various OSINT APIs"""

    @staticmethod
    async def check_virustotal(artifact: str, artifact_type: str) -> Dict:
        """Check artifact with VirusTotal API"""
        api_key = settings.get_api_key('virustotal')
        if not api_key:
            return {"service": "VirusTotal", "error": "API key not configured"}

        try:
            if artifact_type == "ip":
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{artifact}"
            elif artifact_type == "domain":
                url = f"https://www.virustotal.com/api/v3/domains/{artifact}"
            elif artifact_type == "hash":
                url = f"https://www.virustotal.com/api/v3/files/{artifact}"
            else:
                return {"service": "VirusTotal", "error": "Unsupported type"}

            headers = {"x-apikey": api_key}
            data = await http_client.get_json(url, headers=headers)

            if data:
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})

                return {
                    "service": "VirusTotal",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "harmless": stats.get("harmless", 0)
                }

            return {"service": "VirusTotal", "error": "Not found"}

        except Exception as e:
            logger.error(f"VirusTotal error: {e}")
            return {"service": "VirusTotal", "error": str(e)}

    @staticmethod
    async def check_abuseipdb(ip: str) -> Dict:
        """Check IP with AbuseIPDB API"""
        api_key = settings.get_api_key('abuseipdb')
        if not api_key:
            return {"service": "AbuseIPDB", "error": "API key not configured"}

        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": api_key, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": 90}

            data = await http_client.get_json(url, params=params, headers=headers)

            if data:
                data = data.get("data", {})
                return {
                    "service": "AbuseIPDB",
                    "abuse_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country": data.get("countryCode", "N/A"),
                    "is_whitelisted": data.get("isWhitelisted", False)
                }

            return {"service": "AbuseIPDB", "error": "Not found"}

        except Exception as e:
            logger.error(f"AbuseIPDB error: {e}")
            return {"service": "AbuseIPDB", "error": str(e)}

    @staticmethod
    async def check_greynoise(ip: str) -> Dict:
        """Check IP with GreyNoise API"""
        api_key = settings.get_api_key('greynoise')
        if not api_key:
            return {"service": "GreyNoise", "error": "API key not configured"}

        try:
            url = f"https://api.greynoise.io/v3/community/{ip}"
            headers = {"key": api_key}

            data = await http_client.get_json(url, headers=headers)

            if data:
                return {
                    "service": "GreyNoise",
                    "classification": data.get("classification", "unknown"),
                    "noise": data.get("noise", False),
                    "riot": data.get("riot", False),
                    "name": data.get("name", "N/A")
                }

            return {"service": "GreyNoise", "error": "Not found"}

        except Exception as e:
            logger.error(f"GreyNoise error: {e}")
            return {"service": "GreyNoise", "error": str(e)}

    @staticmethod
    async def check_urlscan(domain: str) -> Dict:
        """Check domain with URLScan.io API"""
        try:
            url = "https://urlscan.io/api/v1/search/"
            params = {"q": f"domain:{domain}"}

            data = await http_client.get_json(url, params=params)

            if data:
                results = data.get("results", [])
                if results:
                    malicious = sum(1 for r in results if r.get("malicious", False))
                    return {
                        "service": "URLScan.io",
                        "total_scans": len(results),
                        "malicious_scans": malicious,
                        "latest_scan": results[0].get("task", {}).get("time", "N/A")
                    }

            return {"service": "URLScan.io", "error": "No results found"}

        except Exception as e:
            logger.error(f"URLScan error: {e}")
            return {"service": "URLScan.io", "error": str(e)}
