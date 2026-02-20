"""IP Address OSINT Module — WHOIS, geolocation, DNS reverse lookup."""
import re
import socket
import subprocess
import logging
from typing import List, Dict, Optional
from eirescope.core.entity import Entity, EntityType, Investigation
from eirescope.modules.base import BaseOSINTModule
from eirescope.utils.http_client import OSINTHTTPClient

logger = logging.getLogger("eirescope.modules.ip")


class IPModule(BaseOSINTModule):
    """IP address reconnaissance — WHOIS, GeoIP, reverse DNS."""

    name = "IP Address Recon"
    description = "Analyze IP: WHOIS lookup, geolocation, reverse DNS, ISP detection, abuse checks"
    supported_entity_types = [EntityType.IP_ADDRESS]
    requires_api_key = False
    icon = "globe"

    def __init__(self, config=None):
        super().__init__(config)
        self.http = OSINTHTTPClient(timeout=10, max_retries=2, rate_limit=0.5)

    def execute(self, entity: Entity, investigation: Investigation) -> List[Entity]:
        """Run IP address reconnaissance."""
        ip = entity.value.strip()
        logger.info(f"Analyzing IP address: {ip}")
        found_entities = []

        # 1. GeoIP Lookup (free API)
        geo_data = self._geoip_lookup(ip)
        if geo_data:
            entity.metadata["geolocation"] = geo_data
            if geo_data.get("country"):
                geo_entity = Entity(
                    entity_type=EntityType.GEO_LOCATION,
                    value=f"{geo_data.get('city', 'Unknown')}, {geo_data.get('country', 'Unknown')}",
                    source_module=self.name,
                    confidence=0.8,
                    metadata=geo_data,
                )
                added = investigation.add_entity(geo_entity)
                investigation.add_relationship(
                    source_id=entity.id,
                    target_id=added.id,
                    rel_type="ip_located_in",
                    confidence=0.8,
                )
                found_entities.append(added)

            # ISP / Organization
            if geo_data.get("isp") or geo_data.get("org"):
                entity.metadata["isp"] = geo_data.get("isp", "")
                entity.metadata["organization"] = geo_data.get("org", "")

        # 2. Reverse DNS
        rdns = self._reverse_dns(ip)
        if rdns:
            entity.metadata["reverse_dns"] = rdns
            # Extract domain from reverse DNS
            domain = self._extract_domain(rdns)
            if domain:
                domain_entity = Entity(
                    entity_type=EntityType.DOMAIN,
                    value=domain,
                    source_module=self.name,
                    confidence=0.7,
                    metadata={"derived_from_ip": ip, "reverse_dns": rdns},
                )
                added = investigation.add_entity(domain_entity)
                investigation.add_relationship(
                    source_id=entity.id,
                    target_id=added.id,
                    rel_type="ip_resolves_to_domain",
                    confidence=0.7,
                )
                found_entities.append(added)

        # 3. WHOIS
        whois_data = self._whois_lookup(ip)
        if whois_data:
            entity.metadata["whois"] = whois_data
            whois_entity = Entity(
                entity_type=EntityType.WHOIS_INFO,
                value=f"WHOIS: {ip}",
                source_module=self.name,
                confidence=0.9,
                metadata=whois_data,
            )
            added = investigation.add_entity(whois_entity)
            investigation.add_relationship(
                source_id=entity.id,
                target_id=added.id,
                rel_type="has_whois_record",
                confidence=0.9,
            )
            found_entities.append(added)

        # 4. Classify IP type
        entity.metadata["ip_type"] = self._classify_ip(ip, geo_data)

        logger.info(f"IP analysis complete: {len(found_entities)} entities discovered")
        return found_entities

    def _geoip_lookup(self, ip: str) -> Optional[Dict]:
        """GeoIP lookup using free ip-api.com service."""
        try:
            resp = self.http.get(
                f"http://ip-api.com/json/{ip}",
                headers={"Accept": "application/json"},
            )
            if resp and resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return {
                        "ip": ip,
                        "country": data.get("country", ""),
                        "country_code": data.get("countryCode", ""),
                        "region": data.get("regionName", ""),
                        "city": data.get("city", ""),
                        "zip": data.get("zip", ""),
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "timezone": data.get("timezone", ""),
                        "isp": data.get("isp", ""),
                        "org": data.get("org", ""),
                        "as": data.get("as", ""),
                        "is_mobile": data.get("mobile", False),
                        "is_proxy": data.get("proxy", False),
                        "is_hosting": data.get("hosting", False),
                    }
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip}: {e}")
        return None

    def _reverse_dns(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            pass
        # Fallback: use dig
        try:
            result = subprocess.run(
                ["dig", "+short", "-x", ip],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip().rstrip(".")
        except Exception:
            pass
        return None

    def _whois_lookup(self, ip: str) -> Optional[Dict]:
        """WHOIS lookup using system whois command."""
        try:
            result = subprocess.run(
                ["whois", ip],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0 and result.stdout:
                return self._parse_whois(result.stdout)
        except FileNotFoundError:
            logger.debug("whois command not found")
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {ip}: {e}")
        return None

    def _parse_whois(self, raw: str) -> Dict:
        """Parse raw WHOIS output into structured data."""
        data = {"raw": raw[:2000]}  # Keep truncated raw
        patterns = {
            "netname": r"(?:NetName|netname):\s*(.+)",
            "org_name": r"(?:OrgName|org-name|organisation):\s*(.+)",
            "country": r"(?:Country|country):\s*(\S+)",
            "address": r"(?:Address|address):\s*(.+)",
            "cidr": r"(?:CIDR|inetnum):\s*(.+)",
            "abuse_email": r"(?:OrgAbuseEmail|abuse-mailbox):\s*(\S+)",
            "created": r"(?:RegDate|created):\s*(.+)",
            "updated": r"(?:Updated|last-modified):\s*(.+)",
        }
        for key, pattern in patterns.items():
            match = re.search(pattern, raw, re.IGNORECASE)
            if match:
                data[key] = match.group(1).strip()
        return data

    def _extract_domain(self, hostname: str) -> Optional[str]:
        """Extract registrable domain from hostname."""
        parts = hostname.rstrip(".").split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return None

    def _classify_ip(self, ip: str, geo_data: Optional[Dict] = None) -> str:
        """Classify IP as residential, hosting, VPN, etc."""
        if geo_data:
            if geo_data.get("is_proxy"):
                return "proxy/VPN"
            if geo_data.get("is_hosting"):
                return "hosting/datacenter"
            if geo_data.get("is_mobile"):
                return "mobile"

        # Check private ranges
        if ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                          "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                          "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                          "172.30.", "172.31.", "192.168.")):
            return "private"
        if ip.startswith("127."):
            return "loopback"

        return "residential/unknown"
