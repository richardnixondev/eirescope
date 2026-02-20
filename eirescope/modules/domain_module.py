"""Domain OSINT Module — DNS records, WHOIS, subdomain enumeration."""
import re
import socket
import subprocess
import logging
from typing import List, Dict, Optional
from eirescope.core.entity import Entity, EntityType, Investigation
from eirescope.modules.base import BaseOSINTModule
from eirescope.utils.http_client import OSINTHTTPClient

logger = logging.getLogger("eirescope.modules.domain")


class DomainModule(BaseOSINTModule):
    """Domain reconnaissance — DNS, WHOIS, subdomain discovery."""

    name = "Domain Recon"
    description = "Analyze domain: DNS records (A, MX, NS, TXT), WHOIS registration, subdomain enumeration via crt.sh"
    supported_entity_types = [EntityType.DOMAIN]
    requires_api_key = False
    icon = "globe"

    def __init__(self, config=None):
        super().__init__(config)
        self.http = OSINTHTTPClient(timeout=10, max_retries=2, rate_limit=0.5)

    def execute(self, entity: Entity, investigation: Investigation) -> List[Entity]:
        """Run domain reconnaissance."""
        domain = entity.value.lower().strip().rstrip(".")
        logger.info(f"Analyzing domain: {domain}")
        found_entities = []

        # 1. DNS A records → get IP addresses
        a_records = self._dns_lookup(domain, "A")
        entity.metadata["a_records"] = a_records
        for ip in a_records:
            ip_entity = Entity(
                entity_type=EntityType.IP_ADDRESS,
                value=ip,
                source_module=self.name,
                confidence=0.95,
                metadata={"domain": domain, "record_type": "A"},
            )
            added = investigation.add_entity(ip_entity)
            investigation.add_relationship(
                source_id=entity.id,
                target_id=added.id,
                rel_type="domain_resolves_to",
                confidence=0.95,
            )
            found_entities.append(added)

        # 2. MX records
        mx_records = self._dns_lookup(domain, "MX")
        entity.metadata["mx_records"] = mx_records

        # 3. NS records
        ns_records = self._dns_lookup(domain, "NS")
        entity.metadata["ns_records"] = ns_records

        # 4. TXT records (SPF, DKIM, DMARC)
        txt_records = self._dns_lookup(domain, "TXT")
        entity.metadata["txt_records"] = txt_records
        entity.metadata["spf"] = [r for r in txt_records if "spf" in r.lower()]
        entity.metadata["dmarc"] = self._dns_lookup(f"_dmarc.{domain}", "TXT")

        # 5. WHOIS
        whois_data = self._whois_lookup(domain)
        if whois_data:
            entity.metadata["whois"] = whois_data
            whois_entity = Entity(
                entity_type=EntityType.WHOIS_INFO,
                value=f"WHOIS: {domain}",
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

            # Extract registrant email if available
            if whois_data.get("registrant_email"):
                email_entity = Entity(
                    entity_type=EntityType.EMAIL,
                    value=whois_data["registrant_email"],
                    source_module=self.name,
                    confidence=0.7,
                    metadata={"source": "domain_whois", "domain": domain},
                )
                added = investigation.add_entity(email_entity)
                investigation.add_relationship(
                    source_id=entity.id,
                    target_id=added.id,
                    rel_type="domain_registered_by",
                    confidence=0.7,
                )
                found_entities.append(added)

        # 6. Subdomain enumeration via crt.sh
        subdomains = self._enumerate_subdomains(domain)
        entity.metadata["subdomains"] = subdomains
        entity.metadata["subdomain_count"] = len(subdomains)
        for sub in subdomains[:20]:  # Limit to top 20
            sub_entity = Entity(
                entity_type=EntityType.DOMAIN,
                value=sub,
                source_module=self.name,
                confidence=0.8,
                metadata={"parent_domain": domain, "source": "crt.sh"},
            )
            added = investigation.add_entity(sub_entity)
            investigation.add_relationship(
                source_id=entity.id,
                target_id=added.id,
                rel_type="has_subdomain",
                confidence=0.8,
            )
            found_entities.append(added)

        # 7. Security analysis
        entity.metadata["security"] = {
            "has_spf": len(entity.metadata.get("spf", [])) > 0,
            "has_dmarc": len(entity.metadata.get("dmarc", [])) > 0,
            "mx_count": len(mx_records),
            "ns_count": len(ns_records),
        }

        logger.info(f"Domain analysis complete: {len(found_entities)} entities discovered")
        return found_entities

    def _dns_lookup(self, domain: str, record_type: str) -> List[str]:
        """DNS lookup using dig command."""
        try:
            result = subprocess.run(
                ["dig", "+short", record_type, domain],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                records = []
                for line in result.stdout.strip().split("\n"):
                    val = line.strip().rstrip(".")
                    if val and not val.startswith(";"):
                        # For MX, extract just the server name
                        if record_type == "MX":
                            parts = val.split()
                            if len(parts) >= 2:
                                val = f"{parts[0]} {parts[1].rstrip('.')}"
                        records.append(val)
                return records
        except Exception as e:
            logger.debug(f"DNS {record_type} lookup failed for {domain}: {e}")

        # Fallback for A records using socket
        if record_type == "A":
            try:
                results = socket.getaddrinfo(domain, None, socket.AF_INET)
                return list(set(r[4][0] for r in results))
            except Exception:
                pass
        return []

    def _whois_lookup(self, domain: str) -> Optional[Dict]:
        """WHOIS lookup for domain."""
        try:
            result = subprocess.run(
                ["whois", domain],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0 and result.stdout:
                return self._parse_whois(result.stdout)
        except FileNotFoundError:
            logger.debug("whois command not found")
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {domain}: {e}")
        return None

    def _parse_whois(self, raw: str) -> Dict:
        """Parse domain WHOIS output."""
        data = {"raw": raw[:3000]}
        patterns = {
            "registrar": r"(?:Registrar|registrar):\s*(.+)",
            "creation_date": r"(?:Creation Date|created):\s*(.+)",
            "expiry_date": r"(?:Registry Expiry Date|Expiration Date|expires):\s*(.+)",
            "updated_date": r"(?:Updated Date|last-modified):\s*(.+)",
            "registrant_name": r"(?:Registrant Name|registrant):\s*(.+)",
            "registrant_org": r"(?:Registrant Organization|org):\s*(.+)",
            "registrant_email": r"(?:Registrant Email|e-mail):\s*(\S+@\S+)",
            "registrant_country": r"(?:Registrant Country|country):\s*(\S+)",
            "name_servers": r"(?:Name Server|nserver):\s*(\S+)",
            "status": r"(?:Domain Status|status):\s*(.+)",
        }
        for key, pattern in patterns.items():
            matches = re.findall(pattern, raw, re.IGNORECASE)
            if matches:
                if key in ("name_servers", "status"):
                    data[key] = [m.strip().lower() for m in matches]
                else:
                    data[key] = matches[0].strip()
        return data

    def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains using crt.sh certificate transparency."""
        try:
            resp = self.http.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers={"Accept": "application/json"},
            )
            if resp and resp.status_code == 200:
                certs = resp.json()
                subdomains = set()
                for cert in certs:
                    name = cert.get("name_value", "")
                    for entry in name.split("\n"):
                        entry = entry.strip().lower()
                        if entry.endswith(domain) and entry != domain:
                            # Skip wildcards
                            if not entry.startswith("*"):
                                subdomains.add(entry)
                return sorted(subdomains)
        except Exception as e:
            logger.debug(f"Subdomain enumeration failed for {domain}: {e}")
        return []
