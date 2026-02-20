"""Input validation and normalization for EireScope."""
import re
import socket
from typing import Tuple, Optional
from eirescope.core.entity import EntityType


class EntityValidator:
    """Validates and normalizes user-provided search inputs."""

    EMAIL_RE = re.compile(
        r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    )
    USERNAME_RE = re.compile(r"^[a-zA-Z0-9._\-]{1,64}$")
    PHONE_RE = re.compile(r"^\+?[\d\s\-\(\)]{7,20}$")
    DOMAIN_RE = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )
    IP_V4_RE = re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
    )

    @classmethod
    def validate_email(cls, value: str) -> bool:
        return bool(cls.EMAIL_RE.match(value.strip()))

    @classmethod
    def validate_username(cls, value: str) -> bool:
        return bool(cls.USERNAME_RE.match(value.strip()))

    @classmethod
    def validate_phone(cls, value: str) -> bool:
        cleaned = re.sub(r"[\s\-\(\)]", "", value.strip())
        return bool(re.match(r"^\+?\d{7,15}$", cleaned))

    @classmethod
    def validate_domain(cls, value: str) -> bool:
        return bool(cls.DOMAIN_RE.match(value.strip().lower()))

    @classmethod
    def validate_ip(cls, value: str) -> bool:
        v = value.strip()
        if cls.IP_V4_RE.match(v):
            return True
        try:
            socket.inet_pton(socket.AF_INET6, v)
            return True
        except (socket.error, OSError):
            return False

    @classmethod
    def normalize(cls, value: str, entity_type: EntityType) -> str:
        """Normalize input based on entity type."""
        v = value.strip()
        if entity_type == EntityType.EMAIL:
            return v.lower()
        if entity_type == EntityType.DOMAIN:
            return v.lower().rstrip(".")
        if entity_type == EntityType.PHONE:
            return re.sub(r"[\s\-\(\)]", "", v)
        if entity_type == EntityType.IP_ADDRESS:
            return v
        if entity_type == EntityType.USERNAME:
            return v.lstrip("@")
        return v

    @classmethod
    def detect_type(cls, value: str) -> Optional[EntityType]:
        """Auto-detect entity type from input value."""
        v = value.strip()
        if cls.validate_email(v):
            return EntityType.EMAIL
        if cls.validate_ip(v):
            return EntityType.IP_ADDRESS
        if cls.validate_phone(v) and (v.startswith("+") or len(re.sub(r"\D", "", v)) >= 10):
            return EntityType.PHONE
        if cls.validate_domain(v):
            return EntityType.DOMAIN
        if cls.validate_username(v):
            return EntityType.USERNAME
        return None

    @classmethod
    def validate_and_normalize(cls, value: str, entity_type: EntityType) -> Tuple[bool, str]:
        """Validate and normalize input. Returns (is_valid, normalized_value)."""
        validators = {
            EntityType.EMAIL: cls.validate_email,
            EntityType.USERNAME: cls.validate_username,
            EntityType.PHONE: cls.validate_phone,
            EntityType.DOMAIN: cls.validate_domain,
            EntityType.IP_ADDRESS: cls.validate_ip,
        }
        validator = validators.get(entity_type)
        if validator and not validator(value):
            return False, value
        return True, cls.normalize(value, entity_type)
