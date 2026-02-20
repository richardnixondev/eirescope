"""Social Media OSINT Module — Profile discovery across platforms."""
import logging
from typing import List
from eirescope.core.entity import Entity, EntityType, Investigation
from eirescope.modules.base import BaseOSINTModule
from eirescope.utils.http_client import OSINTHTTPClient

logger = logging.getLogger("eirescope.modules.social")

# Social platforms that allow email-based search or public profile lookup
SOCIAL_SEARCH_URLS = {
    "GitHub": "https://api.github.com/search/users?q={}",
    "Gravatar": "https://en.gravatar.com/{}.json",
}


class SocialMediaModule(BaseOSINTModule):
    """Cross-platform social media profile discovery."""

    name = "Social Media Discovery"
    description = "Find social media profiles linked to emails, usernames, or phone numbers"
    supported_entity_types = [EntityType.EMAIL, EntityType.USERNAME]
    requires_api_key = False
    icon = "users"

    def __init__(self, config=None):
        super().__init__(config)
        self.http = OSINTHTTPClient(timeout=8, max_retries=2, rate_limit=0.3)

    def execute(self, entity: Entity, investigation: Investigation) -> List[Entity]:
        """Discover social profiles from entity."""
        logger.info(f"Social media discovery for: {entity.value} ({entity.entity_type.value})")
        found_entities = []

        if entity.entity_type == EntityType.USERNAME:
            found_entities.extend(self._search_github_user(entity, investigation))

        if entity.entity_type == EntityType.EMAIL:
            found_entities.extend(self._search_by_email(entity, investigation))

        logger.info(f"Social discovery complete: {len(found_entities)} profiles found")
        return found_entities

    def _search_github_user(self, entity: Entity, investigation: Investigation) -> List[Entity]:
        """Search GitHub for user profile details."""
        found = []
        username = entity.value
        try:
            resp = self.http.get(f"https://api.github.com/users/{username}")
            if resp and resp.status_code == 200:
                data = resp.json()
                profile_entity = Entity(
                    entity_type=EntityType.SOCIAL_PROFILE,
                    value=data.get("html_url", f"https://github.com/{username}"),
                    source_module=self.name,
                    confidence=0.95,
                    metadata={
                        "platform": "GitHub",
                        "username": data.get("login"),
                        "name": data.get("name"),
                        "bio": data.get("bio"),
                        "company": data.get("company"),
                        "location": data.get("location"),
                        "blog": data.get("blog"),
                        "public_repos": data.get("public_repos"),
                        "followers": data.get("followers"),
                        "following": data.get("following"),
                        "created_at": data.get("created_at"),
                        "avatar_url": data.get("avatar_url"),
                    },
                )
                added = investigation.add_entity(profile_entity)
                investigation.add_relationship(
                    source_id=entity.id,
                    target_id=added.id,
                    rel_type="has_github_profile",
                    confidence=0.95,
                )
                found.append(added)

                # Extract email from GitHub profile if public
                if data.get("email"):
                    email_entity = Entity(
                        entity_type=EntityType.EMAIL,
                        value=data["email"],
                        source_module=self.name,
                        confidence=0.9,
                        metadata={"source": "github_profile"},
                    )
                    added_email = investigation.add_entity(email_entity)
                    investigation.add_relationship(
                        source_id=added.id,
                        target_id=added_email.id,
                        rel_type="profile_has_email",
                        confidence=0.9,
                    )
                    found.append(added_email)

                # Extract blog/website
                if data.get("blog"):
                    url_entity = Entity(
                        entity_type=EntityType.URL,
                        value=data["blog"],
                        source_module=self.name,
                        confidence=0.9,
                        metadata={"source": "github_profile"},
                    )
                    added_url = investigation.add_entity(url_entity)
                    investigation.add_relationship(
                        source_id=added.id,
                        target_id=added_url.id,
                        rel_type="profile_links_to",
                        confidence=0.9,
                    )
                    found.append(added_url)

        except Exception as e:
            logger.debug(f"GitHub search failed: {e}")
        return found

    def _search_by_email(self, entity: Entity, investigation: Investigation) -> List[Entity]:
        """Search for profiles linked to an email address."""
        found = []
        email = entity.value

        # Check Gravatar
        import hashlib
        email_hash = hashlib.md5(email.lower().encode()).hexdigest()
        try:
            resp = self.http.get(f"https://en.gravatar.com/{email_hash}.json")
            if resp and resp.status_code == 200:
                data = resp.json()
                if "entry" in data and data["entry"]:
                    entry = data["entry"][0]
                    profile_entity = Entity(
                        entity_type=EntityType.SOCIAL_PROFILE,
                        value=entry.get("profileUrl", f"https://gravatar.com/{email_hash}"),
                        source_module=self.name,
                        confidence=0.9,
                        metadata={
                            "platform": "Gravatar",
                            "display_name": entry.get("displayName"),
                            "about": entry.get("aboutMe"),
                            "location": entry.get("currentLocation"),
                            "accounts": [
                                {"platform": a.get("shortname"), "url": a.get("url")}
                                for a in entry.get("accounts", [])
                            ],
                        },
                    )
                    added = investigation.add_entity(profile_entity)
                    investigation.add_relationship(
                        source_id=entity.id,
                        target_id=added.id,
                        rel_type="email_has_gravatar",
                        confidence=0.9,
                    )
                    found.append(added)

                    # Extract linked accounts from Gravatar
                    for account in entry.get("accounts", []):
                        if account.get("url"):
                            acc_entity = Entity(
                                entity_type=EntityType.SOCIAL_PROFILE,
                                value=account["url"],
                                source_module=self.name,
                                confidence=0.85,
                                metadata={
                                    "platform": account.get("shortname", "unknown"),
                                    "source": "gravatar_linked",
                                },
                            )
                            added_acc = investigation.add_entity(acc_entity)
                            investigation.add_relationship(
                                source_id=added.id,
                                target_id=added_acc.id,
                                rel_type="gravatar_links_to",
                                confidence=0.85,
                            )
                            found.append(added_acc)
        except Exception as e:
            logger.debug(f"Gravatar search failed: {e}")

        return found
