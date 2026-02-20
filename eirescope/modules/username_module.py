"""Username OSINT Module — Search username across social platforms (Sherlock-like)."""
import logging
from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed
from eirescope.core.entity import Entity, EntityType, Investigation
from eirescope.modules.base import BaseOSINTModule
from eirescope.utils.http_client import OSINTHTTPClient

logger = logging.getLogger("eirescope.modules.username")

# Platforms to check: name, URL template ({} = username), error indicator
PLATFORMS = [
    # Major Social Media
    {"name": "GitHub", "url": "https://github.com/{}", "category": "development"},
    {"name": "GitLab", "url": "https://gitlab.com/{}", "category": "development"},
    {"name": "Twitter/X", "url": "https://x.com/{}", "category": "social"},
    {"name": "Instagram", "url": "https://www.instagram.com/{}/", "category": "social"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{}", "category": "social"},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{}", "category": "social"},
    {"name": "YouTube", "url": "https://www.youtube.com/@{}", "category": "social"},
    {"name": "Twitch", "url": "https://www.twitch.tv/{}", "category": "social"},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{}/", "category": "social"},
    {"name": "Tumblr", "url": "https://{}.tumblr.com", "category": "social"},
    # Professional
    {"name": "LinkedIn", "url": "https://www.linkedin.com/in/{}", "category": "professional"},
    {"name": "Medium", "url": "https://medium.com/@{}", "category": "professional"},
    {"name": "Dev.to", "url": "https://dev.to/{}", "category": "development"},
    {"name": "HackerNews", "url": "https://news.ycombinator.com/user?id={}", "category": "development"},
    {"name": "StackOverflow", "url": "https://stackoverflow.com/users/?tab=accounts&SearchText={}", "category": "development"},
    {"name": "Keybase", "url": "https://keybase.io/{}", "category": "security"},
    # Communication
    {"name": "Telegram", "url": "https://t.me/{}", "category": "communication"},
    {"name": "Mastodon (social)", "url": "https://mastodon.social/@{}", "category": "social"},
    # Content & Media
    {"name": "SoundCloud", "url": "https://soundcloud.com/{}", "category": "media"},
    {"name": "Spotify", "url": "https://open.spotify.com/user/{}", "category": "media"},
    {"name": "Flickr", "url": "https://www.flickr.com/people/{}", "category": "media"},
    {"name": "Vimeo", "url": "https://vimeo.com/{}", "category": "media"},
    {"name": "Dailymotion", "url": "https://www.dailymotion.com/{}", "category": "media"},
    # Gaming
    {"name": "Steam Community", "url": "https://steamcommunity.com/id/{}", "category": "gaming"},
    {"name": "Xbox Gamertag", "url": "https://xboxgamertag.com/search/{}", "category": "gaming"},
    # Forums & Communities
    {"name": "HackerOne", "url": "https://hackerone.com/{}", "category": "security"},
    {"name": "Bugcrowd", "url": "https://bugcrowd.com/{}", "category": "security"},
    {"name": "Gravatar", "url": "https://en.gravatar.com/{}", "category": "other"},
    {"name": "About.me", "url": "https://about.me/{}", "category": "professional"},
    {"name": "Behance", "url": "https://www.behance.net/{}", "category": "professional"},
    {"name": "Dribbble", "url": "https://dribbble.com/{}", "category": "professional"},
    # Tech & Code
    {"name": "Replit", "url": "https://replit.com/@{}", "category": "development"},
    {"name": "CodePen", "url": "https://codepen.io/{}", "category": "development"},
    {"name": "npm", "url": "https://www.npmjs.com/~{}", "category": "development"},
    {"name": "PyPI", "url": "https://pypi.org/user/{}/", "category": "development"},
    {"name": "Docker Hub", "url": "https://hub.docker.com/u/{}", "category": "development"},
    # News & Blogging
    {"name": "Blogger", "url": "https://{}.blogspot.com", "category": "blogging"},
    {"name": "WordPress", "url": "https://{}.wordpress.com", "category": "blogging"},
    {"name": "Substack", "url": "https://{}.substack.com", "category": "blogging"},
    # Irish / EU specific
    {"name": "Boards.ie", "url": "https://www.boards.ie/member/{}", "category": "irish"},
]


class UsernameModule(BaseOSINTModule):
    """Search for a username across multiple social platforms."""

    name = "Username Search"
    description = "Search a username across 40+ social platforms and websites (Sherlock-like)"
    supported_entity_types = [EntityType.USERNAME]
    requires_api_key = False
    icon = "user-search"

    def __init__(self, config=None):
        super().__init__(config)
        self.http = OSINTHTTPClient(
            timeout=config.get("timeout", 8) if config else 8,
            max_retries=1,
            rate_limit=0.1,
        )
        self.max_workers = 10

    def _check_platform(self, platform: dict, username: str) -> dict:
        """Check if username exists on a single platform."""
        url = platform["url"].format(username)
        try:
            exists = self.http.check_url_exists(url, timeout=6)
            return {
                "platform": platform["name"],
                "url": url,
                "exists": exists,
                "category": platform["category"],
            }
        except Exception as e:
            logger.debug(f"Error checking {platform['name']}: {e}")
            return {
                "platform": platform["name"],
                "url": url,
                "exists": False,
                "category": platform["category"],
                "error": str(e),
            }

    def execute(self, entity: Entity, investigation: Investigation) -> List[Entity]:
        """Search username across all platforms using thread pool."""
        username = entity.value
        logger.info(f"Searching username '{username}' across {len(PLATFORMS)} platforms")

        found_entities = []
        results = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._check_platform, p, username): p
                for p in PLATFORMS
            }
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                if result["exists"]:
                    profile_entity = Entity(
                        entity_type=EntityType.SOCIAL_PROFILE,
                        value=result["url"],
                        source_module=self.name,
                        confidence=0.85,
                        metadata={
                            "platform": result["platform"],
                            "category": result["category"],
                            "username": username,
                        },
                    )
                    added = investigation.add_entity(profile_entity)
                    investigation.add_relationship(
                        source_id=entity.id,
                        target_id=added.id,
                        rel_type="has_profile_on",
                        confidence=0.85,
                        evidence={"url": result["url"], "platform": result["platform"]},
                    )
                    found_entities.append(added)
                    logger.info(f"  [+] Found: {result['platform']} → {result['url']}")

        # Store summary in the original entity metadata
        entity.metadata["platforms_checked"] = len(PLATFORMS)
        entity.metadata["profiles_found"] = len(found_entities)
        entity.metadata["results_summary"] = [
            {"platform": r["platform"], "url": r["url"], "found": r["exists"]}
            for r in sorted(results, key=lambda x: x["platform"])
        ]

        logger.info(f"Username search complete: {len(found_entities)}/{len(PLATFORMS)} platforms found")
        return found_entities
