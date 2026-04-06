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

            grey = await OSINTServices.check_greynoise(artifact_value)
            if "error" not in grey:
                results.append(grey)

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
            # OSINT services
            urlscan = await OSINTServices.check_urlscan(artifact_value)
            if "error" not in urlscan:
                results.append(urlscan)

            vt = await OSINTServices.check_virustotal(artifact_value, "domain")
            if "error" not in vt:
                results.append(vt)

            # Advanced analysis
            whois = await AdvancedAnalysis.get_whois_info(artifact_value)
            if "error" not in whois:
                results.append(whois)

            dns = await AdvancedAnalysis.get_dns_records(artifact_value)
            results.append(dns)

            ssl = await AdvancedAnalysis.get_ssl_info(artifact_value)
            if "error" not in ssl:
                results.append(ssl)

        elif artifact_type == "hash":
            vt = await OSINTServices.check_virustotal(artifact_value, "hash")
            if "error" not in vt:
                results.append(vt)

        logger.info(f"Analyzed {artifact_type}: {artifact_value} - {len(results)} results")
        return results
