"""Phone Number OSINT Module — Validation, carrier detection, geolocation."""
import re
import logging
from typing import List, Dict, Optional
from eirescope.core.entity import Entity, EntityType, Investigation
from eirescope.modules.base import BaseOSINTModule

logger = logging.getLogger("eirescope.modules.phone")

# Irish carrier prefixes (mobile)
IRISH_CARRIERS = {
    "083": "Three Ireland",
    "085": "Three Ireland",
    "086": "Vodafone Ireland",
    "087": "Vodafone Ireland",
    "089": "Three Ireland",
    "088": "Tesco Mobile / Three MVNO",
}

# Country codes
COUNTRY_CODES = {
    "353": {"country": "Ireland", "iso": "IE", "name": "Éire"},
    "44": {"country": "United Kingdom", "iso": "GB", "name": "UK"},
    "1": {"country": "United States/Canada", "iso": "US/CA", "name": "North America"},
    "33": {"country": "France", "iso": "FR", "name": "France"},
    "49": {"country": "Germany", "iso": "DE", "name": "Germany"},
    "34": {"country": "Spain", "iso": "ES", "name": "Spain"},
    "39": {"country": "Italy", "iso": "IT", "name": "Italy"},
    "31": {"country": "Netherlands", "iso": "NL", "name": "Netherlands"},
    "32": {"country": "Belgium", "iso": "BE", "name": "Belgium"},
    "48": {"country": "Poland", "iso": "PL", "name": "Poland"},
    "351": {"country": "Portugal", "iso": "PT", "name": "Portugal"},
    "45": {"country": "Denmark", "iso": "DK", "name": "Denmark"},
    "46": {"country": "Sweden", "iso": "SE", "name": "Sweden"},
    "47": {"country": "Norway", "iso": "NO", "name": "Norway"},
    "358": {"country": "Finland", "iso": "FI", "name": "Finland"},
    "91": {"country": "India", "iso": "IN", "name": "India"},
    "86": {"country": "China", "iso": "CN", "name": "China"},
    "81": {"country": "Japan", "iso": "JP", "name": "Japan"},
    "55": {"country": "Brazil", "iso": "BR", "name": "Brazil"},
    "61": {"country": "Australia", "iso": "AU", "name": "Australia"},
}


class PhoneModule(BaseOSINTModule):
    """Analyze and enrich phone number data."""

    name = "Phone Number Analysis"
    description = "Validate phone numbers, detect carrier (Irish focus), identify country and number type"
    supported_entity_types = [EntityType.PHONE]
    requires_api_key = False
    icon = "phone"

    def execute(self, entity: Entity, investigation: Investigation) -> List[Entity]:
        """Analyze phone number."""
        phone = entity.value
        logger.info(f"Analyzing phone number: {phone}")
        found_entities = []

        # Normalize
        cleaned = re.sub(r"[\s\-\(\)\.]", "", phone)
        if not cleaned.startswith("+"):
            # Assume Irish if starts with 0
            if cleaned.startswith("0"):
                cleaned = "+353" + cleaned[1:]
            else:
                cleaned = "+" + cleaned

        entity.metadata["normalized"] = cleaned
        entity.metadata["original"] = phone

        # Detect country
        country_info = self._detect_country(cleaned)
        entity.metadata["country"] = country_info

        if country_info:
            geo_entity = Entity(
                entity_type=EntityType.GEO_LOCATION,
                value=country_info.get("country", "Unknown"),
                source_module=self.name,
                confidence=0.9,
                metadata=country_info,
            )
            added = investigation.add_entity(geo_entity)
            investigation.add_relationship(
                source_id=entity.id,
                target_id=added.id,
                rel_type="phone_registered_in",
                confidence=0.9,
            )
            found_entities.append(added)

        # Detect carrier (Irish numbers)
        carrier_info = self._detect_irish_carrier(cleaned)
        if carrier_info:
            entity.metadata["carrier"] = carrier_info
            carrier_entity = Entity(
                entity_type=EntityType.CARRIER_INFO,
                value=carrier_info["carrier"],
                source_module=self.name,
                confidence=0.8,
                metadata=carrier_info,
            )
            added = investigation.add_entity(carrier_entity)
            investigation.add_relationship(
                source_id=entity.id,
                target_id=added.id,
                rel_type="phone_carrier_is",
                confidence=0.8,
            )
            found_entities.append(added)

        # Classify number type
        number_type = self._classify_number_type(cleaned)
        entity.metadata["number_type"] = number_type

        # Format validation
        entity.metadata["is_valid_format"] = self._validate_format(cleaned)
        entity.metadata["e164_format"] = cleaned

        # Irish-specific checks
        if country_info and country_info.get("iso") == "IE":
            entity.metadata["irish_analysis"] = self._analyze_irish_number(cleaned)

        logger.info(f"Phone analysis complete: {len(found_entities)} entities discovered")
        return found_entities

    def _detect_country(self, phone: str) -> Optional[Dict]:
        """Detect country from phone number prefix."""
        digits = phone.lstrip("+")
        # Try 3-digit codes first, then 2-digit, then 1-digit
        for length in [3, 2, 1]:
            prefix = digits[:length]
            if prefix in COUNTRY_CODES:
                return COUNTRY_CODES[prefix].copy()
        return None

    def _detect_irish_carrier(self, phone: str) -> Optional[Dict]:
        """Detect Irish mobile carrier from phone prefix."""
        # Convert +353 to 0-prefix format for carrier lookup
        if phone.startswith("+353"):
            local = "0" + phone[4:]
            prefix = local[:3]
            if prefix in IRISH_CARRIERS:
                return {
                    "carrier": IRISH_CARRIERS[prefix],
                    "prefix": prefix,
                    "type": "mobile",
                    "country": "Ireland",
                }
        return None

    def _classify_number_type(self, phone: str) -> str:
        """Classify number as mobile, landline, VoIP, toll-free, etc."""
        if phone.startswith("+353"):
            local = phone[4:]
            if local.startswith("1"):
                return "landline (Dublin)"
            if local.startswith(("21", "22", "23", "24", "25", "26", "27", "28", "29")):
                return "landline (Munster)"
            if local.startswith(("41", "42", "43", "44", "45", "46", "47", "49")):
                return "landline (Leinster/Ulster)"
            if local.startswith(("51", "52", "53", "54", "56", "57", "58", "59")):
                return "landline (South-East)"
            if local.startswith(("61", "62", "63", "64", "65", "66", "67", "68", "69")):
                return "landline (Mid-West/Kerry)"
            if local.startswith(("71", "74", "76", "90", "91", "93", "94", "95", "96", "97", "98", "99")):
                return "landline (West/North-West)"
            if local.startswith(("83", "85", "86", "87", "89")):
                return "mobile"
            if local.startswith("1800"):
                return "toll-free"
            if local.startswith("1850") or local.startswith("1890"):
                return "shared-cost"
        return "unknown"

    def _validate_format(self, phone: str) -> bool:
        """Validate E.164 format."""
        return bool(re.match(r"^\+\d{7,15}$", phone))

    def _analyze_irish_number(self, phone: str) -> Dict:
        """Additional analysis for Irish phone numbers."""
        local = phone[4:]  # Remove +353
        analysis = {
            "is_irish": True,
            "local_number": "0" + local,
            "international_format": phone,
        }

        # Check if it's a premium rate number
        if local.startswith("15"):
            analysis["warning"] = "Premium rate number"
            analysis["risk_level"] = "high"

        # Check for known VoIP ranges
        if local.startswith("76"):
            analysis["note"] = "VoIP number range — may be harder to trace"
            analysis["is_voip"] = True

        return analysis
