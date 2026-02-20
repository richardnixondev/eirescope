"""Core data models for EireScope investigations."""
import uuid
from enum import Enum
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any


class EntityType(Enum):
    """All searchable/discoverable entity types."""
    EMAIL = "email"
    USERNAME = "username"
    PHONE = "phone"
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    COMPANY = "company"
    PERSON = "person"
    SOCIAL_PROFILE = "social_profile"
    URL = "url"
    HASH = "hash"
    BREACH = "breach"
    DNS_RECORD = "dns_record"
    WHOIS_INFO = "whois_info"
    GEO_LOCATION = "geo_location"
    CARRIER_INFO = "carrier_info"


@dataclass
class Entity:
    """Represents a single OSINT artifact discovered during investigation."""
    entity_type: EntityType
    value: str
    source_module: str = ""
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "entity_type": self.entity_type.value,
            "value": self.value,
            "source_module": self.source_module,
            "confidence": self.confidence,
            "metadata": self.metadata,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "Entity":
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            entity_type=EntityType(data["entity_type"]),
            value=data["value"],
            source_module=data.get("source_module", ""),
            confidence=data.get("confidence", 1.0),
            metadata=data.get("metadata", {}),
            created_at=data.get("created_at", datetime.utcnow().isoformat()),
        )


@dataclass
class EntityRelationship:
    """Links two entities with a typed relationship."""
    source_entity_id: str
    target_entity_id: str
    relationship_type: str
    confidence: float = 1.0
    evidence: Dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "source_entity_id": self.source_entity_id,
            "target_entity_id": self.target_entity_id,
            "relationship_type": self.relationship_type,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


@dataclass
class Investigation:
    """A single OSINT investigation session."""
    initial_query: str
    initial_type: EntityType
    entities: List[Entity] = field(default_factory=list)
    relationships: List[EntityRelationship] = field(default_factory=list)
    modules_run: List[str] = field(default_factory=list)
    status: str = "pending"  # pending, running, completed, failed
    notes: str = ""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at: Optional[str] = None

    def add_entity(self, entity: Entity) -> Entity:
        """Add entity, deduplicating by type+value."""
        for existing in self.entities:
            if existing.entity_type == entity.entity_type and existing.value == entity.value:
                existing.metadata.update(entity.metadata)
                return existing
        self.entities.append(entity)
        return entity

    def add_relationship(self, source_id: str, target_id: str,
                         rel_type: str, confidence: float = 1.0,
                         evidence: Dict = None) -> EntityRelationship:
        """Add a relationship between two entities."""
        rel = EntityRelationship(
            source_entity_id=source_id,
            target_entity_id=target_id,
            relationship_type=rel_type,
            confidence=confidence,
            evidence=evidence or {},
        )
        self.relationships.append(rel)
        return rel

    def complete(self):
        self.status = "completed"
        self.completed_at = datetime.utcnow().isoformat()

    def fail(self, reason: str = ""):
        self.status = "failed"
        self.completed_at = datetime.utcnow().isoformat()
        self.notes = reason

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "initial_query": self.initial_query,
            "initial_type": self.initial_type.value,
            "entities": [e.to_dict() for e in self.entities],
            "relationships": [r.to_dict() for r in self.relationships],
            "modules_run": self.modules_run,
            "status": self.status,
            "notes": self.notes,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "entity_count": len(self.entities),
            "relationship_count": len(self.relationships),
        }

    def get_entities_by_type(self, entity_type: EntityType) -> List[Entity]:
        return [e for e in self.entities if e.entity_type == entity_type]

    def get_entity_by_id(self, entity_id: str) -> Optional[Entity]:
        for e in self.entities:
            if e.id == entity_id:
                return e
        return None
