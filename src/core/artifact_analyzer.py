"""Main artifact analyzer orchestrator"""

import logging
from typing import Dict, List
from .osint_services import OSINTServices
from .advanced_analysis import AdvancedAnalysis

logger = logging.getLogger(__name__)


class ArtifactAnalyzer:
    """Orchestrates analysis of artifacts using multiple services"""

    async def analyze(self, artifact_type: str, artifact_value: str) -> List[Dict]:
        """
        Analyze artifact using all available services

        Args:
            artifact_type: Type of artifact (ip, domain, hash)
            artifact_value: The artifact value to analyze

        Returns:
            List[Dict]: List of analysis results from all services
        """
        results = []

        if artifact_type == "ip":
            # OSINT services
            abuse = await OSINTServices.check_abuseipdb(artifact_value)
            if "error" not in abuse:
                results.append(abuse)

           # grey = await OSINTServices.check_greynoise(artifact_value)
           # if "error" not in grey:
           #     results.append(grey)

            vt = await OSINTServices.check_virustotal(artifact_value, "ip")
            if "error" not in vt:
                results.append(vt)

            # Advanced analysis
            ports = await AdvancedAnalysis.scan_ports(artifact_value)
            results.append(ports)

            geo = await AdvancedAnalysis.get_geolocation(artifact_value)
            if "error" not in geo:
                results.append(geo)

        elif artifact_type == "domain":
            results = []
            
            # URLScan.io
            urlscan = await OSINTServices.check_urlscan(artifact_value)
            results.append(urlscan)
            logger.info(f"URLScan result: service={urlscan.get('service')}, error={urlscan.get('error', 'no error')}")

            # VirusTotal
            vt = await OSINTServices.check_virustotal(artifact_value, "domain")
            results.append(vt)
            logger.info(f"VirusTotal result: service={vt.get('service')}, error={vt.get('error', 'no error')}")

            # WHOIS
            whois = await AdvancedAnalysis.get_whois_info(artifact_value)
            results.append(whois)
            logger.info(f"WHOIS result: service={whois.get('service')}, error={whois.get('error', 'no error')}")

            # DNS Records
            dns = await AdvancedAnalysis.get_dns_records(artifact_value)
            results.append(dns)
            logger.info(f"DNS result: service={dns.get('service')}, error={dns.get('error', 'no error')}")

            # SSL/TLS
            ssl = await AdvancedAnalysis.get_ssl_info(artifact_value)
            results.append(ssl)
            logger.info(f"SSL result: service={ssl.get('service')}, error={ssl.get('error', 'no error')}")

            logger.info(f"Analyzed domain: {artifact_value} - {len(results)} results")

        elif artifact_type == "hash":
            vt = await OSINTServices.check_virustotal(artifact_value, "hash")
            if "error" not in vt:
                results.append(vt)

        logger.info(f"Analyzed {artifact_type}: {artifact_value} - {len(results)} results")
        return results
