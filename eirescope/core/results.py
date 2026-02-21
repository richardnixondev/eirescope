"""Result aggregation and analysis utilities."""
from typing import Dict, List
from collections import Counter
from eirescope.core.entity import Investigation, EntityType


def summarize_investigation(investigation: Investigation) -> Dict:
    """Generate a summary of an investigation for display."""
    entity_counts = Counter(e.entity_type.value for e in investigation.entities)
    rel_counts = Counter(r.relationship_type for r in investigation.relationships)

    # Build graph data for D3.js visualization
    nodes = []
    for e in investigation.entities:
        nodes.append({
            "id": e.id,
            "label": _truncate(e.value, 40),
            "type": e.entity_type.value,
            "confidence": e.confidence,
            "source": e.source_module,
        })

    links = []
    for r in investigation.relationships:
        links.append({
            "source": r.source_entity_id,
            "target": r.target_entity_id,
            "type": r.relationship_type,
            "confidence": r.confidence,
        })

    return {
        "id": investigation.id,
        "query": investigation.initial_query,
        "query_type": investigation.initial_type.value,
        "status": investigation.status,
        "created_at": investigation.created_at,
        "completed_at": investigation.completed_at,
        "total_entities": len(investigation.entities),
        "total_relationships": len(investigation.relationships),
        "entity_counts": dict(entity_counts),
        "relationship_counts": dict(rel_counts),
        "modules_run": investigation.modules_run,
        "graph": {"nodes": nodes, "links": links},
        "entities": [e.to_dict() for e in investigation.entities],
        "relationships": [r.to_dict() for r in investigation.relationships],
    }


def _truncate(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."
