"""Base class for all EireScope OSINT modules."""
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from eirescope.core.entity import Entity, EntityType, Investigation


class BaseOSINTModule(ABC):
    """Abstract base for all OSINT plugins.

    Every module must define:
        - name: human-readable module name
        - description: what this module does
        - supported_entity_types: which entity types it can process
        - requires_api_key: whether an API key is needed
    """

    name: str = "Base Module"
    description: str = ""
    supported_entity_types: List[EntityType] = []
    requires_api_key: bool = False
    api_key_name: str = ""
    icon: str = "search"

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.api_key = self.config.get(self.api_key_name, "")

    def can_handle(self, entity_type: EntityType) -> bool:
        """Check if this module supports the given entity type."""
        return entity_type in self.supported_entity_types

    @abstractmethod
    def execute(self, entity: Entity, investigation: Investigation) -> List[Entity]:
        """Execute the OSINT module against an entity.

        Args:
            entity: The entity to investigate.
            investigation: The parent investigation (for adding relationships).

        Returns:
            List of newly discovered entities.
        """
        pass

    def get_metadata(self) -> Dict:
        return {
            "name": self.name,
            "description": self.description,
            "supported_types": [t.value for t in self.supported_entity_types],
            "requires_api_key": self.requires_api_key,
            "icon": self.icon,
        }
