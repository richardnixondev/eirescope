"""Email OSINT Module — Email enrichment, breach checks, and domain analysis."""
import re
import socket
import logging
from typing import List, Dict, Optional
from eirescope.core.entity import Entity, EntityType, Investigation
from eirescope.modules.base import BaseOSINTModule
from eirescope.utils.http_client import OSINTHTTPClient

logger = logging.getLogger("eirescope.modules.email")


class EmailModule(BaseOSINTModule):
    """Enrich email addresses with breach data, domain info, and associated accounts."""

    name = "Email Enrichment"
    description = "Analyze email: validate domain, check breaches (HIBP), extract domain info, find associated usernames"
    supported_entity_types = [EntityType.EMAIL]
    requires_api_key = False  # Core features work without API key; HIBP needs key for full results
    api_key_name = "HIBP_API_KEY"
    icon = "mail"

    def __init__(self, config=None):
        super().__init__(config)
        self.http = OSINTHTTPClient(timeout=10, max_retries=2, rate_limit=0.5)

    def execute(self, entity: Entity, investigation: Investigation) -> List[Entity]:
        """Run email enrichment pipeline."""
        email = entity.value.lower().strip()
        logger.info(f"Enriching email: {email}")
        found_entities = []

        local_part, domain = email.split("@", 1)

        # 1. Extract username from email local part
        username_entity = Entity(
            entity_type=EntityType.USERNAME,
            value=local_part,
            source_module=self.name,
            confidence=0.7,
            metadata={"derived_from": email, "note": "Username extracted from email local part"},
        )
        added = investigation.add_entity(username_entity)
        investigation.add_relationship(
            source_id=entity.id,
            target_id=added.id,
            rel_type="email_contains_username",
            confidence=0.7,
        )
        found_entities.append(added)

        # 2. Extract and enrich domain
        domain_entity = Entity(
            entity_type=EntityType.DOMAIN,
            value=domain,
            source_module=self.name,
            confidence=1.0,
            metadata={"derived_from": email},
        )
        added_domain = investigation.add_entity(domain_entity)
        investigation.add_relationship(
            source_id=entity.id,
            target_id=added_domain.id,
            rel_type="email_hosted_on",
            confidence=1.0,
        )
        found_entities.append(added_domain)

        # 3. Validate domain via MX records
        mx_info = self._check_mx_records(domain)
        entity.metadata["mx_records"] = mx_info
        entity.metadata["domain"] = domain
        entity.metadata["local_part"] = local_part
        entity.metadata["is_valid_domain"] = len(mx_info) > 0

        # 4. Detect email provider
        provider = self._detect_provider(domain, mx_info)
        entity.metadata["email_provider"] = provider

        # 5. Check for known disposable email domains
        entity.metadata["is_disposable"] = self._is_disposable_domain(domain)

        # 6. Check HaveIBeenPwned (if API key available)
        breach_results = self._check_breaches(email)
        if breach_results:
            entity.metadata["breaches"] = breach_results
            entity.metadata["breach_count"] = len(breach_results)
            for breach in breach_results:
                breach_entity = Entity(
                    entity_type=EntityType.BREACH,
                    value=breach.get("name", "Unknown Breach"),
                    source_module=self.name,
                    confidence=0.95,
                    metadata=breach,
                )
                added_breach = investigation.add_entity(breach_entity)
                investigation.add_relationship(
                    source_id=entity.id,
                    target_id=added_breach.id,
                    rel_type="found_in_breach",
                    confidence=0.95,
                    evidence={"breach_name": breach.get("name"), "breach_date": breach.get("date")},
                )
                found_entities.append(added_breach)

        # 7. Check Gravatar for profile
        gravatar_info = self._check_gravatar(email)
        if gravatar_info:
            entity.metadata["gravatar"] = gravatar_info

        logger.info(f"Email enrichment complete: {len(found_entities)} entities discovered")
        return found_entities

    def _check_mx_records(self, domain: str) -> List[Dict]:
        """Check MX records for the email domain."""
        try:
            import subprocess
            result = subprocess.run(
                ["dig", "+short", "MX", domain],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                records = []
                for line in result.stdout.strip().split("\n"):
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        records.append({
                            "priority": int(parts[0]),
                            "server": parts[1].rstrip("."),
                        })
                return sorted(records, key=lambda x: x["priority"])
        except Exception as e:
            logger.debug(f"MX lookup failed for {domain}: {e}")

        # Fallback: try socket
        try:
            socket.getaddrinfo(domain, 25)
            return [{"priority": 0, "server": domain, "note": "fallback check"}]
        except Exception:
            pass
        return []

    def _detect_provider(self, domain: str, mx_records: List[Dict]) -> str:
        """Detect email provider from domain or MX records."""
        domain_lower = domain.lower()
        mx_str = " ".join([r.get("server", "") for r in mx_records]).lower()

        provider_map = {
            "gmail.com": "Google (Gmail)",
            "googlemail.com": "Google (Gmail)",
            "outlook.com": "Microsoft (Outlook)",
            "hotmail.com": "Microsoft (Hotmail)",
            "live.com": "Microsoft (Live)",
            "yahoo.com": "Yahoo",
            "protonmail.com": "ProtonMail",
            "proton.me": "ProtonMail",
            "icloud.com": "Apple (iCloud)",
            "me.com": "Apple",
            "aol.com": "AOL",
            "zoho.com": "Zoho",
        }

        if domain_lower in provider_map:
            return provider_map[domain_lower]

        if "google" in mx_str or "gmail" in mx_str:
            return "Google Workspace"
        if "outlook" in mx_str or "microsoft" in mx_str:
            return "Microsoft 365"
        if "protonmail" in mx_str:
            return "ProtonMail"
        if "zoho" in mx_str:
            return "Zoho"

        return "Custom/Unknown"

    def _is_disposable_domain(self, domain: str) -> bool:
        """Check if domain is a known disposable/temporary email provider."""
        disposable_domains = {
            "tempmail.com", "guerrillamail.com", "mailinator.com",
            "throwaway.email", "temp-mail.org", "fakeinbox.com",
            "sharklasers.com", "guerrillamailblock.com", "grr.la",
            "dispostable.com", "yopmail.com", "trashmail.com",
            "maildrop.cc", "10minutemail.com", "tempail.com",
            "burnermail.io", "mailnesia.com", "tempr.email",
        }
        return domain.lower() in disposable_domains

    def _check_breaches(self, email: str) -> List[Dict]:
        """Check multiple breach databases for exposed credentials."""
        all_breaches = []

        # 1. HaveIBeenPwned (requires API key for full results)
        if self.api_key:
            try:
                resp = self.http.get(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                    headers={
                        "hibp-api-key": self.api_key,
                        "User-Agent": "EireScope-OSINT",
                    },
                )
                if resp and resp.status_code == 200:
                    for b in resp.json():
                        all_breaches.append({
                            "name": b.get("Name", "Unknown"),
                            "date": b.get("BreachDate", ""),
                            "description": b.get("Description", ""),
                            "data_classes": b.get("DataClasses", []),
                            "is_verified": b.get("IsVerified", False),
                            "source": "HaveIBeenPwned",
                        })
            except Exception as e:
                logger.debug(f"HIBP check failed: {e}")

        # 2. XposedOrNot (free, no key needed)
        try:
            resp = self.http.get(
                f"https://api.xposedornot.com/v1/check-email/{email}"
            )
            if resp and resp.status_code == 200:
                data = resp.json()
                if "breaches" in data:
                    for b in data["breaches"]:
                        if not any(x["name"] == b for x in all_breaches):
                            all_breaches.append({"name": b, "source": "XposedOrNot"})
        except Exception as e:
            logger.debug(f"XposedOrNot check failed: {e}")

        # 3. BreachDirectory (free tier)
        try:
            resp = self.http.post(
                "https://breachdirectory.p.rapidapi.com/",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com",
                    "X-RapidAPI-Key": self.config.get("RAPIDAPI_KEY", ""),
                } if self.config.get("RAPIDAPI_KEY") else {},
                data={"func": "auto", "term": email},
            )
            if resp and resp.status_code == 200:
                data = resp.json()
                if data.get("success") and data.get("result"):
                    for entry in data["result"]:
                        src = entry.get("sources", ["Unknown"])
                        for s in src:
                            if not any(x["name"] == s for x in all_breaches):
                                all_breaches.append({
                                    "name": s,
                                    "has_password": entry.get("has_password", False),
                                    "source": "BreachDirectory",
                                })
        except Exception as e:
            logger.debug(f"BreachDirectory check failed: {e}")

        # 4. LeakCheck (free tier — 10 req/day)
        leakcheck_key = self.config.get("LEAKCHECK_API_KEY", "")
        if leakcheck_key:
            try:
                resp = self.http.get(
                    f"https://leakcheck.io/api/public?check={email}",
                    headers={"X-API-Key": leakcheck_key},
                )
                if resp and resp.status_code == 200:
                    data = resp.json()
                    if data.get("success") and data.get("sources"):
                        for s in data["sources"]:
                            name = s.get("name", "Unknown")
                            if not any(x["name"] == name for x in all_breaches):
                                all_breaches.append({
                                    "name": name,
                                    "date": s.get("date", ""),
                                    "source": "LeakCheck",
                                })
            except Exception as e:
                logger.debug(f"LeakCheck check failed: {e}")

        # 5. EmailRep.io (free, no key — reputation scoring)
        try:
            resp = self.http.get(
                f"https://emailrep.io/{email}",
                headers={"User-Agent": "EireScope-OSINT"},
            )
            if resp and resp.status_code == 200:
                data = resp.json()
                if data.get("details", {}).get("credentials_leaked"):
                    all_breaches.append({
                        "name": "EmailRep Credential Leak",
                        "reputation": data.get("reputation", ""),
                        "suspicious": data.get("suspicious", False),
                        "references": data.get("references", 0),
                        "details": {
                            "malicious_activity": data.get("details", {}).get("malicious_activity", False),
                            "spam": data.get("details", {}).get("spam", False),
                            "free_provider": data.get("details", {}).get("free_provider", False),
                            "data_breach": data.get("details", {}).get("data_breach", False),
                            "last_seen": data.get("details", {}).get("last_seen", ""),
                        },
                        "source": "EmailRep.io",
                    })
                # Store reputation data in entity metadata regardless
                self._emailrep_data = {
                    "reputation": data.get("reputation", ""),
                    "suspicious": data.get("suspicious", False),
                    "references": data.get("references", 0),
                    "profiles": data.get("details", {}).get("profiles", []),
                }
        except Exception as e:
            logger.debug(f"EmailRep check failed: {e}")

        return all_breaches

    def _check_gravatar(self, email: str) -> Optional[Dict]:
        """Check for Gravatar profile associated with email."""
        import hashlib
        email_hash = hashlib.md5(email.lower().encode()).hexdigest()
        url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
        try:
            resp = self.http.head(url)
            if resp and resp.status_code == 200:
                return {
                    "has_gravatar": True,
                    "avatar_url": f"https://www.gravatar.com/avatar/{email_hash}",
                    "profile_url": f"https://gravatar.com/{email_hash}",
                }
        except Exception:
            pass
        return None
