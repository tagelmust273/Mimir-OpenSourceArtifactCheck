"""Advanced analysis modules (WHOIS, DNS, SSL, Port Scan, GeoIP)"""

import asyncio
import socket
import ssl
import whois
import dns.resolver
import aiohttp
from typing import Dict, List


class AdvancedAnalysis:
    """Advanced artifact analysis"""

    @staticmethod
    async def get_whois_info(domain: str) -> Dict:
        """Get WHOIS information for domain"""
        try:
            w = await asyncio.to_thread(whois.whois, domain)

            return {
                "service": "WHOIS",
                "registrar": w.registrar,
                "creation_date": str(w.creation_date) if w.creation_date else "N/A",
                "expiration_date": str(w.expiration_date) if w.expiration_date else "N/A",
                "name_servers": w.name_servers[:3] if w.name_servers else [],
                "organization": getattr(w, 'org', 'N/A'),
                "country": getattr(w, 'country', 'N/A'),
                "emails": getattr(w, 'emails', [])
            }
        except Exception as e:
            return {"service": "WHOIS", "error": str(e)}

    @staticmethod
    async def get_dns_records(domain: str) -> Dict:
        """Get DNS records for domain"""
        records = {}

        try:
            a_records = await asyncio.to_thread(dns.resolver.resolve, domain, 'A')
            records['A'] = [str(r) for r in a_records]
        except:
            records['A'] = []

        try:
            mx_records = await asyncio.to_thread(dns.resolver.resolve, domain, 'MX')
            records['MX'] = [{'exchange': str(r.exchange), 'preference': r.preference} for r in mx_records]
        except:
            records['MX'] = []

        try:
            txt_records = await asyncio.to_thread(dns.resolver.resolve, domain, 'TXT')
            records['TXT'] = [str(r) for r in txt_records][:3]
        except:
            records['TXT'] = []

        try:
            ns_records = await asyncio.to_thread(dns.resolver.resolve, domain, 'NS')
            records['NS'] = [str(r) for r in ns_records]
        except:
            records['NS'] = []

        return {"service": "DNS Records", "records": records}

    @staticmethod
    async def get_ssl_info(domain: str) -> Dict:
        """Get SSL/TLS certificate information"""
        try:
            def get_cert():
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        return ssock.getpeercert()

            cert = await asyncio.to_thread(get_cert)

            return {
                "service": "SSL/TLS",
                "issuer": cert.get('issuer', [('CN', 'N/A')])[0][1],
                "subject": cert.get('subject', [('CN', 'N/A')])[0][1],
                "not_before": cert.get('notBefore', 'N/A'),
                "not_after": cert.get('notAfter', 'N/A'),
                "serial_number": cert.get('serialNumber', 'N/A'),
                "version": cert.get('version', 'N/A')
            }
        except Exception as e:
            return {"service": "SSL/TLS", "error": str(e)}

    @staticmethod
    async def scan_ports(ip: str) -> Dict:
        """Scan common ports on IP address"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5900, 8080]
        open_ports = []

        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Proxy"
        }

        async def check_port(port):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=2.0
                )
                writer.close()
                await writer.wait_closed()
                open_ports.append({"port": port, "service": services.get(port, "Unknown")})
            except:
                pass

        tasks = [check_port(port) for port in common_ports]
        await asyncio.gather(*tasks)

        return {
            "service": "Port Scanner",
            "ip": ip,
            "open_ports": open_ports,
            "total_scanned": len(common_ports),
            "open_count": len(open_ports)
        }

    @staticmethod
    async def get_geolocation(ip: str) -> Dict:
        """Get geolocation information for IP"""
        try:
            url = f"http://ip-api.com/json/{ip}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('status') == 'success':
                            return {
                                "service": "GeoLocation",
                                "country": data.get('country', 'N/A'),
                                "region": data.get('regionName', 'N/A'),
                                "city": data.get('city', 'N/A'),
                                "latitude": data.get('lat', 0),
                                "longitude": data.get('lon', 0),
                                "isp": data.get('isp', 'N/A'),
                                "org": data.get('org', 'N/A'),
                                "timezone": data.get('timezone', 'N/A')
                            }
            return {"service": "GeoLocation", "error": "Location not found"}
        except Exception as e:
            return {"service": "GeoLocation", "error": str(e)}
