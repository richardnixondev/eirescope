"""Investigation Engine — orchestrates OSINT modules and aggregates results."""
import logging
from typing import List, Optional, Dict
from datetime import datetime
from eirescope.core.entity import Entity, EntityType, Investigation
from eirescope.core.plugin_manager import PluginManager
from eirescope.utils.validators import EntityValidator
from eirescope.utils.exceptions import ValidationError, ModuleError

logger = logging.getLogger("eirescope.core.engine")


class InvestigationEngine:
    """Main orchestration engine for OSINT investigations."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.plugin_manager = PluginManager(config=self.config)

    def investigate(self, query: str, entity_type: str = None,
                    module_filter: List[str] = None) -> Investigation:
        """Run a full OSINT investigation.

        Args:
            query: The search value (email, username, IP, etc.)
            entity_type: Entity type string (auto-detected if None)
            module_filter: Optional list of module names to run (runs all if None)

        Returns:
            Investigation with all discovered entities and relationships.
        """
        # 1. Validate and detect entity type
        if entity_type:
            try:
                etype = EntityType(entity_type)
            except ValueError:
                raise ValidationError(f"Unknown entity type: {entity_type}")
        else:
            etype = EntityValidator.detect_type(query)
            if not etype:
                raise ValidationError(
                    f"Could not auto-detect entity type for: {query}. "
                    "Please specify the entity type."
                )

        # 2. Validate and normalize input
        is_valid, normalized = EntityValidator.validate_and_normalize(query, etype)
        if not is_valid:
            raise ValidationError(f"Invalid {etype.value}: {query}")

        logger.info(f"Starting investigation: {normalized} (type: {etype.value})")

        # 3. Create investigation
        investigation = Investigation(
            initial_query=normalized,
            initial_type=etype,
            status="running",
        )

        # 4. Create the seed entity
        seed_entity = Entity(
            entity_type=etype,
            value=normalized,
            source_module="user_input",
            confidence=1.0,
        )
        investigation.add_entity(seed_entity)

        # 5. Get applicable modules
        modules = self.plugin_manager.get_modules_for_entity(etype)
        if module_filter:
            modules = [m for m in modules if m.name in module_filter]

        if not modules:
            logger.warning(f"No modules available for entity type: {etype.value}")
            investigation.complete()
            return investigation

        # 6. Execute each module sequentially
        for module in modules:
            try:
                logger.info(f"Running module: {module.name}")
                new_entities = module.execute(seed_entity, investigation)
                investigation.modules_run.append(module.name)
                logger.info(f"Module {module.name} found {len(new_entities)} entities")
            except Exception as e:
                logger.error(f"Module {module.name} failed: {e}")
                investigation.modules_run.append(f"{module.name} (FAILED)")

        # 7. Complete investigation
        investigation.complete()
        logger.info(
            f"Investigation complete: {len(investigation.entities)} entities, "
            f"{len(investigation.relationships)} relationships"
        )
        return investigation

    def get_available_modules(self) -> List[Dict]:
        """List all available OSINT modules."""
        return self.plugin_manager.list_modules()

    def get_supported_types(self) -> List[str]:
        """Get entity types that have at least one module."""
        return self.plugin_manager.get_supported_types()
