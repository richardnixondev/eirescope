"""Irish Companies Registration Office (CRO) Module — Company & director lookup via Open Data API."""
import logging
from typing import List, Dict, Optional
from eirescope.core.entity import Entity, EntityType, Investigation
from eirescope.modules.base import BaseOSINTModule
from eirescope.utils.http_client import OSINTHTTPClient

logger = logging.getLogger("eirescope.modules.irish_cro")

# CRO Open Data Portal — CKAN API
CRO_API_BASE = "https://opendata.cro.ie/api/3/action"
CRO_COMPANY_RESOURCE = "e64eb540-fb97-44c2-b461-766f2babbdf6"

# Also available: CORE search (public web)
CRO_CORE_SEARCH = "https://core.cro.ie/api/company/search"


class IrishCROModule(BaseOSINTModule):
    """Search Irish Companies Registration Office for company and director data."""

    name = "Irish CRO Lookup"
    description = "Search Irish Companies Office (CRO) open data for company registrations, directors and status"
    supported_entity_types = [EntityType.COMPANY, EntityType.PERSON, EntityType.USERNAME, EntityType.DOMAIN]
    requires_api_key = False
    icon = "building"

    def __init__(self, config=None):
        super().__init__(config)
        self.http = OSINTHTTPClient(timeout=15, max_retries=2, rate_limit=0.5)

    def execute(self, entity: Entity, investigation: Investigation) -> List[Entity]:
        """Search CRO for company/person data."""
        query = entity.value
        logger.info(f"CRO lookup for: {query}")
        found_entities = []

        # For domains, extract the name part (e.g., "acme" from "acme.ie")
        if entity.entity_type == EntityType.DOMAIN:
            query = query.split(".")[0]

        # 1. Search CRO Open Data (CKAN API)
        results = self._search_ckan(query)
        if results:
            entity.metadata["cro_results_count"] = len(results)
            for company in results[:10]:  # Top 10 matches
                company_entity = Entity(
                    entity_type=EntityType.COMPANY,
                    value=company.get("company_name", "Unknown"),
                    source_module=self.name,
                    confidence=0.85,
                    metadata={
                        "company_number": company.get("company_num", ""),
                        "company_name": company.get("company_name", ""),
                        "company_status": company.get("company_status_desc", ""),
                        "company_type": company.get("company_type_desc", ""),
                        "registered_address": company.get("company_addr_1", ""),
                        "address_2": company.get("company_addr_2", ""),
                        "address_3": company.get("company_addr_3", ""),
                        "address_4": company.get("company_addr_4", ""),
                        "eircode": company.get("company_addr_eircode", ""),
                        "registration_date": company.get("company_reg_date", ""),
                        "last_annual_return": company.get("last_arr_date", ""),
                        "last_accounts_date": company.get("last_accounts_date", ""),
                        "place_of_business": company.get("place_of_business", ""),
                        "source": "CRO Open Data",
                        "cro_url": f"https://core.cro.ie/company/{company.get('company_num', '')}",
                    },
                )
                added = investigation.add_entity(company_entity)
                investigation.add_relationship(
                    source_id=entity.id,
                    target_id=added.id,
                    rel_type="search_found_company",
                    confidence=0.85,
                    evidence={"query": query, "company_number": company.get("company_num", "")},
                )
                found_entities.append(added)

        # 2. Try CORE search as well (web-based)
        core_results = self._search_core(query)
        if core_results:
            for company in core_results[:5]:
                name = company.get("companyName", "")
                if not any(e.value == name for e in found_entities):
                    company_entity = Entity(
                        entity_type=EntityType.COMPANY,
                        value=name,
                        source_module=self.name,
                        confidence=0.8,
                        metadata={
                            "company_number": company.get("companyNumber", ""),
                            "company_name": name,
                            "company_status": company.get("companyStatusDesc", ""),
                            "company_type": company.get("companyTypeDesc", ""),
                            "registered_address": company.get("companyAddress", ""),
                            "source": "CRO CORE",
                            "cro_url": f"https://core.cro.ie/company/{company.get('companyNumber', '')}",
                        },
                    )
                    added = investigation.add_entity(company_entity)
                    investigation.add_relationship(
                        source_id=entity.id,
                        target_id=added.id,
                        rel_type="search_found_company",
                        confidence=0.8,
                    )
                    found_entities.append(added)

        logger.info(f"CRO lookup complete: {len(found_entities)} companies found")
        return found_entities

    def _search_ckan(self, query: str) -> List[Dict]:
        """Search CRO Open Data Portal via CKAN datastore API."""
        try:
            resp = self.http.get(
                f"{CRO_API_BASE}/datastore_search",
                params={
                    "resource_id": CRO_COMPANY_RESOURCE,
                    "q": query,
                    "limit": 15,
                },
            )
            if resp and resp.status_code == 200:
                data = resp.json()
                if data.get("success"):
                    return data.get("result", {}).get("records", [])
        except Exception as e:
            logger.debug(f"CKAN search failed: {e}")
        return []

    def _search_core(self, query: str) -> List[Dict]:
        """Search CRO CORE website API."""
        try:
            resp = self.http.get(
                "https://services.cro.ie/cw/company",
                params={
                    "company_name": query,
                    "skip": 0,
                    "take": 10,
                },
                headers={"Accept": "application/json"},
            )
            if resp and resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    return data
                return data.get("companies", data.get("results", []))
        except Exception as e:
            logger.debug(f"CORE search failed: {e}")
        return []
