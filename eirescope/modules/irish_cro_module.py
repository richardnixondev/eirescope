"""Irish Companies Registration Office (CRO) Module — Company & director lookup via Open Data + CWS API."""
import logging
import base64
import os
from typing import List, Dict
from eirescope.core.entity import Entity, EntityType, Investigation
from eirescope.modules.base import BaseOSINTModule
from eirescope.utils.http_client import OSINTHTTPClient

logger = logging.getLogger("eirescope.modules.irish_cro")

# CRO Open Data Portal — CKAN API (individual company records)
CRO_CKAN_BASE = "https://opendata.cro.ie/api/3/action"
CRO_COMPANY_RESOURCE = "3fef41bc-b8f4-4b10-8434-ce51c29b1bba"

# CRO Company Web Services (CWS) — RESTful API
CRO_CWS_BASE = "https://services.cro.ie/cws"

# Test credentials (limited to 'ryanair', 'google', company_num 83740)
CRO_TEST_EMAIL = "[email protected]"
CRO_TEST_KEY = "da093a04-c9d7-46d7-9c83-9c9f8630d5e0"


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
        # CWS API credentials (optional — falls back to test creds)
        self.cws_email = os.environ.get("CRO_EMAIL", "")
        self.cws_key = os.environ.get("CRO_API_KEY", "")

    def _get_cws_auth_header(self) -> Dict[str, str]:
        """Build Basic Auth header for CWS API."""
        email = self.cws_email or CRO_TEST_EMAIL
        key = self.cws_key or CRO_TEST_KEY
        token = base64.b64encode(f"{email}:{key}".encode()).decode()
        return {"Authorization": f"Basic {token}", "Accept": "application/json"}

    def execute(self, entity: Entity, investigation: Investigation) -> List[Entity]:
        """Search CRO for company/person data."""
        query = entity.value
        logger.info(f"CRO lookup for: {query}")
        found_entities = []

        # For domains, extract the name part (e.g., "acme" from "acme.ie")
        if entity.entity_type == EntityType.DOMAIN:
            query = query.split(".")[0]

        # 1. Search CRO Open Data (CKAN API — full company register)
        ckan_results = self._search_ckan(query)
        if ckan_results:
            entity.metadata["cro_ckan_results"] = len(ckan_results)
            for company in ckan_results[:10]:
                comp_name = (
                    company.get("company_name")
                    or company.get("Company Name")
                    or company.get("company_name_english")
                    or "Unknown"
                )
                comp_num = str(
                    company.get("company_num")
                    or company.get("Company Number")
                    or company.get("company_number")
                    or ""
                )
                company_entity = Entity(
                    entity_type=EntityType.COMPANY,
                    value=comp_name,
                    source_module=self.name,
                    confidence=0.85,
                    metadata={
                        "company_number": comp_num,
                        "company_name": comp_name,
                        "company_status": company.get("company_status", company.get("company_status_desc", "")),
                        "company_type": company.get("company_type_desc", company.get("company_type", "")),
                        "registered_address": company.get("company_addr_1", company.get("company_address_1", "")),
                        "address_2": company.get("company_addr_2", company.get("company_address_2", "")),
                        "address_3": company.get("company_addr_3", company.get("company_address_3", "")),
                        "address_4": company.get("company_addr_4", company.get("company_address_4", "")),
                        "county": company.get("County", company.get("county", "")),
                        "registration_date": company.get("company_reg_date", ""),
                        "last_annual_return": company.get("last_arr_date", ""),
                        "last_accounts_date": company.get("last_accounts_date", ""),
                        "dissolved_date": company.get("comp_dissolved_date", ""),
                        "source": "CRO Open Data (CKAN)",
                        "cro_url": f"https://core.cro.ie/company/{comp_num}" if comp_num else "",
                    },
                )
                added = investigation.add_entity(company_entity)
                investigation.add_relationship(
                    source_id=entity.id,
                    target_id=added.id,
                    rel_type="cro_company_record",
                    confidence=0.85,
                    evidence={"query": query, "company_number": comp_num},
                )
                found_entities.append(added)

        # 2. Also try CKAN SQL search for more flexible matching
        if not ckan_results:
            sql_results = self._search_ckan_sql(query)
            if sql_results:
                entity.metadata["cro_sql_results"] = len(sql_results)
                for company in sql_results[:10]:
                    comp_name = (
                        company.get("company_name")
                        or company.get("Company Name")
                        or "Unknown"
                    )
                    # Skip if already found
                    if any(e.value == comp_name for e in found_entities):
                        continue
                    comp_num = str(company.get("company_num", company.get("Company Number", "")))
                    company_entity = Entity(
                        entity_type=EntityType.COMPANY,
                        value=comp_name,
                        source_module=self.name,
                        confidence=0.80,
                        metadata={
                            "company_number": comp_num,
                            "company_name": comp_name,
                            "company_status": company.get("company_status", ""),
                            "county": company.get("County", ""),
                            "source": "CRO Open Data (SQL)",
                            "cro_url": f"https://core.cro.ie/company/{comp_num}" if comp_num else "",
                        },
                    )
                    added = investigation.add_entity(company_entity)
                    investigation.add_relationship(
                        source_id=entity.id,
                        target_id=added.id,
                        rel_type="cro_company_record",
                        confidence=0.80,
                    )
                    found_entities.append(added)

        # 3. Try CWS API (services.cro.ie) — requires API key or test mode
        cws_results = self._search_cws(query)
        if cws_results:
            entity.metadata["cro_cws_results"] = len(cws_results)
            for company in cws_results[:5]:
                name = company.get("company_name", "")
                if not name or any(e.value == name for e in found_entities):
                    continue
                comp_num = str(company.get("company_num", ""))
                company_entity = Entity(
                    entity_type=EntityType.COMPANY,
                    value=name,
                    source_module=self.name,
                    confidence=0.90,
                    metadata={
                        "company_number": comp_num,
                        "company_name": name,
                        "company_status": company.get("company_status_desc", company.get("status", "")),
                        "company_type": company.get("company_type_desc", company.get("type", "")),
                        "registered_address": company.get("company_addr_1", ""),
                        "source": "CRO CWS API",
                        "cro_url": f"https://core.cro.ie/company/{comp_num}" if comp_num else "",
                    },
                )
                added = investigation.add_entity(company_entity)
                investigation.add_relationship(
                    source_id=entity.id,
                    target_id=added.id,
                    rel_type="cro_company_record",
                    confidence=0.90,
                )
                found_entities.append(added)

        if not found_entities:
            entity.metadata["cro_note"] = (
                "No results found. The CKAN open data may use a different resource format. "
                "Try searching directly at https://core.cro.ie or set CRO_EMAIL and CRO_API_KEY "
                "environment variables for full CWS API access."
            )
            logger.warning(f"CRO: no results for '{query}' across all sources")

        logger.info(f"CRO lookup complete: {len(found_entities)} companies found")
        return found_entities

    # ── CKAN full-text search ──────────────────────────────────────────

    def _search_ckan(self, query: str) -> List[Dict]:
        """Search CRO Open Data Portal via CKAN datastore full-text search."""
        try:
            resp = self.http.get(
                f"{CRO_CKAN_BASE}/datastore_search",
                params={
                    "resource_id": CRO_COMPANY_RESOURCE,
                    "q": query,
                    "limit": 15,
                },
            )
            if resp and resp.status_code == 200:
                data = resp.json()
                if data.get("success"):
                    records = data.get("result", {}).get("records", [])
                    if records:
                        logger.info(f"CKAN search returned {len(records)} records")
                        return records
                    else:
                        logger.info("CKAN search returned 0 records")
            elif resp:
                logger.warning(f"CKAN returned status {resp.status_code}")
        except Exception as e:
            logger.warning(f"CKAN search failed: {e}")
        return []

    def _search_ckan_sql(self, query: str) -> List[Dict]:
        """Search CKAN using SQL API for flexible LIKE matching."""
        try:
            # Escape single quotes in query
            safe_q = query.replace("'", "''")
            sql = (
                f'SELECT * FROM "{CRO_COMPANY_RESOURCE}" '
                f"WHERE \"company_name\" ILIKE '%{safe_q}%' "
                f"LIMIT 15"
            )
            resp = self.http.get(
                f"{CRO_CKAN_BASE}/datastore_search_sql",
                params={"sql": sql},
            )
            if resp and resp.status_code == 200:
                data = resp.json()
                if data.get("success"):
                    records = data.get("result", {}).get("records", [])
                    if records:
                        logger.info(f"CKAN SQL search returned {len(records)} records")
                        return records
            elif resp:
                logger.warning(f"CKAN SQL returned status {resp.status_code}")
        except Exception as e:
            logger.warning(f"CKAN SQL search failed: {e}")
        return []

    # ── CWS REST API ───────────────────────────────────────────────────

    def _search_cws(self, query: str) -> List[Dict]:
        """Search CRO Company Web Services (CWS) REST API."""
        try:
            resp = self.http.get(
                f"{CRO_CWS_BASE}/companies",
                params={
                    "company_name": query,
                    "company_bus_ind": "C",
                    "skip": 0,
                    "max": 10,
                    "htmlEnc": "false",
                },
                headers=self._get_cws_auth_header(),
            )
            if resp and resp.status_code == 200:
                data = resp.json()
                # CWS returns a list or an object with companies
                if isinstance(data, list):
                    logger.info(f"CWS returned {len(data)} companies")
                    return data
                companies = data.get("companies", data.get("results", []))
                if companies:
                    logger.info(f"CWS returned {len(companies)} companies")
                    return companies
            elif resp:
                logger.warning(f"CWS returned status {resp.status_code}: {resp.text[:200]}")
        except Exception as e:
            logger.warning(f"CWS search failed: {e}")
        return []
