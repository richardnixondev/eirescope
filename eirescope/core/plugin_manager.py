"""Plugin manager — auto-discovers and loads OSINT modules."""
import logging
from typing import List, Dict, Optional
from eirescope.core.entity import EntityType
from eirescope.modules.base import BaseOSINTModule
from eirescope.modules.username_module import UsernameModule
from eirescope.modules.email_module import EmailModule
from eirescope.modules.phone_module import PhoneModule
from eirescope.modules.ip_module import IPModule
from eirescope.modules.domain_module import DomainModule
from eirescope.modules.social_module import SocialMediaModule
from eirescope.modules.irish_cro_module import IrishCROModule

logger = logging.getLogger("eirescope.core.plugins")

# Registry of all available modules
AVAILABLE_MODULES = [
    UsernameModule,
    EmailModule,
    PhoneModule,
    IPModule,
    DomainModule,
    SocialMediaModule,
    IrishCROModule,
]


class PluginManager:
    """Manages OSINT module loading and discovery."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.modules: Dict[str, BaseOSINTModule] = {}
        self._load_modules()

    def _load_modules(self):
        """Load all registered OSINT modules."""
        for module_class in AVAILABLE_MODULES:
            try:
                module = module_class(config=self.config)
                self.modules[module.name] = module
                logger.info(f"Loaded module: {module.name}")
            except Exception as e:
                logger.error(f"Failed to load module {module_class.__name__}: {e}")

    def get_modules_for_entity(self, entity_type: EntityType) -> List[BaseOSINTModule]:
        """Get all modules that can handle a given entity type."""
        return [m for m in self.modules.values() if m.can_handle(entity_type)]

    def get_module(self, name: str) -> Optional[BaseOSINTModule]:
        """Get a specific module by name."""
        return self.modules.get(name)

    def list_modules(self) -> List[Dict]:
        """List all available modules with metadata."""
        return [m.get_metadata() for m in self.modules.values()]

    def get_supported_types(self) -> List[str]:
        """Get all entity types supported by at least one module."""
        types = set()
        for module in self.modules.values():
            for t in module.supported_entity_types:
                types.add(t.value)
        return sorted(types)
