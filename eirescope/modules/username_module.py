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
    # ═══════════════════════════════════════════
    # Major Social Media
    # ═══════════════════════════════════════════
    {"name": "Twitter/X", "url": "https://x.com/{}", "category": "social"},
    {"name": "Instagram", "url": "https://www.instagram.com/{}/", "category": "social"},
    {"name": "Facebook", "url": "https://www.facebook.com/{}", "category": "social"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{}", "category": "social"},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{}", "category": "social"},
    {"name": "YouTube", "url": "https://www.youtube.com/@{}", "category": "social"},
    {"name": "Twitch", "url": "https://www.twitch.tv/{}", "category": "social"},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{}/", "category": "social"},
    {"name": "Tumblr", "url": "https://{}.tumblr.com", "category": "social"},
    {"name": "Snapchat", "url": "https://www.snapchat.com/add/{}", "category": "social"},
    {"name": "VK", "url": "https://vk.com/{}", "category": "social"},
    {"name": "OK.ru", "url": "https://ok.ru/profile/{}", "category": "social"},
    {"name": "Threads", "url": "https://www.threads.net/@{}", "category": "social"},
    {"name": "Bluesky", "url": "https://bsky.app/profile/{}.bsky.social", "category": "social"},
    # ═══════════════════════════════════════════
    # Mastodon / Fediverse
    # ═══════════════════════════════════════════
    {"name": "Mastodon.social", "url": "https://mastodon.social/@{}", "category": "fediverse"},
    {"name": "Mastodon.online", "url": "https://mastodon.online/@{}", "category": "fediverse"},
    {"name": "Mastodon.world", "url": "https://mastodon.world/@{}", "category": "fediverse"},
    {"name": "Mstdn.social", "url": "https://mstdn.social/@{}", "category": "fediverse"},
    {"name": "Fosstodon", "url": "https://fosstodon.org/@{}", "category": "fediverse"},
    {"name": "Infosec.exchange", "url": "https://infosec.exchange/@{}", "category": "fediverse"},
    {"name": "Hachyderm.io", "url": "https://hachyderm.io/@{}", "category": "fediverse"},
    {"name": "Lemmy.world", "url": "https://lemmy.world/u/{}", "category": "fediverse"},
    {"name": "Pixelfed", "url": "https://pixelfed.social/{}", "category": "fediverse"},
    # ═══════════════════════════════════════════
    # Professional / Career
    # ═══════════════════════════════════════════
    {"name": "LinkedIn", "url": "https://www.linkedin.com/in/{}", "category": "professional"},
    {"name": "About.me", "url": "https://about.me/{}", "category": "professional"},
    {"name": "Behance", "url": "https://www.behance.net/{}", "category": "professional"},
    {"name": "Dribbble", "url": "https://dribbble.com/{}", "category": "professional"},
    {"name": "Fiverr", "url": "https://www.fiverr.com/{}", "category": "professional"},
    {"name": "Freelancer", "url": "https://www.freelancer.com/u/{}", "category": "professional"},
    {"name": "Upwork", "url": "https://www.upwork.com/freelancers/~{}", "category": "professional"},
    {"name": "AngelList", "url": "https://angel.co/u/{}", "category": "professional"},
    {"name": "Crunchbase", "url": "https://www.crunchbase.com/person/{}", "category": "professional"},
    {"name": "Glassdoor", "url": "https://www.glassdoor.com/member/{}", "category": "professional"},
    # ═══════════════════════════════════════════
    # Development / Tech
    # ═══════════════════════════════════════════
    {"name": "GitHub", "url": "https://github.com/{}", "category": "development"},
    {"name": "GitLab", "url": "https://gitlab.com/{}", "category": "development"},
    {"name": "Bitbucket", "url": "https://bitbucket.org/{}/", "category": "development"},
    {"name": "Dev.to", "url": "https://dev.to/{}", "category": "development"},
    {"name": "HackerNews", "url": "https://news.ycombinator.com/user?id={}", "category": "development"},
    {"name": "StackOverflow", "url": "https://stackoverflow.com/users/?tab=accounts&SearchText={}", "category": "development"},
    {"name": "Replit", "url": "https://replit.com/@{}", "category": "development"},
    {"name": "CodePen", "url": "https://codepen.io/{}", "category": "development"},
    {"name": "JSFiddle", "url": "https://jsfiddle.net/user/{}/", "category": "development"},
    {"name": "Glitch", "url": "https://glitch.com/@{}", "category": "development"},
    {"name": "npm", "url": "https://www.npmjs.com/~{}", "category": "development"},
    {"name": "PyPI", "url": "https://pypi.org/user/{}/", "category": "development"},
    {"name": "RubyGems", "url": "https://rubygems.org/profiles/{}", "category": "development"},
    {"name": "Crates.io", "url": "https://crates.io/users/{}", "category": "development"},
    {"name": "Packagist", "url": "https://packagist.org/users/{}/", "category": "development"},
    {"name": "Docker Hub", "url": "https://hub.docker.com/u/{}", "category": "development"},
    {"name": "Codewars", "url": "https://www.codewars.com/users/{}", "category": "development"},
    {"name": "HackerRank", "url": "https://www.hackerrank.com/{}", "category": "development"},
    {"name": "LeetCode", "url": "https://leetcode.com/{}/", "category": "development"},
    {"name": "Codecademy", "url": "https://www.codecademy.com/profiles/{}", "category": "development"},
    {"name": "Kaggle", "url": "https://www.kaggle.com/{}", "category": "development"},
    {"name": "Hashnode", "url": "https://hashnode.com/@{}", "category": "development"},
    {"name": "SourceForge", "url": "https://sourceforge.net/u/{}/", "category": "development"},
    {"name": "Launchpad", "url": "https://launchpad.net/~{}", "category": "development"},
    {"name": "OpenHub", "url": "https://openhub.net/accounts/{}", "category": "development"},
    # ═══════════════════════════════════════════
    # Security / Infosec
    # ═══════════════════════════════════════════
    {"name": "Keybase", "url": "https://keybase.io/{}", "category": "security"},
    {"name": "HackerOne", "url": "https://hackerone.com/{}", "category": "security"},
    {"name": "Bugcrowd", "url": "https://bugcrowd.com/{}", "category": "security"},
    {"name": "TryHackMe", "url": "https://tryhackme.com/p/{}", "category": "security"},
    {"name": "Hack The Box", "url": "https://app.hackthebox.com/users/{}", "category": "security"},
    {"name": "CyberDefenders", "url": "https://cyberdefenders.org/p/{}", "category": "security"},
    # ═══════════════════════════════════════════
    # Communication / Messaging
    # ═══════════════════════════════════════════
    {"name": "Telegram", "url": "https://t.me/{}", "category": "communication"},
    {"name": "Skype", "url": "https://join.skype.com/invite/{}", "category": "communication"},
    {"name": "Discord (Lookup)", "url": "https://discord.com/users/{}", "category": "communication"},
    {"name": "Slack (Public)", "url": "https://{}.slack.com", "category": "communication"},
    # ═══════════════════════════════════════════
    # Content / Media / Music
    # ═══════════════════════════════════════════
    {"name": "SoundCloud", "url": "https://soundcloud.com/{}", "category": "media"},
    {"name": "Spotify", "url": "https://open.spotify.com/user/{}", "category": "media"},
    {"name": "Bandcamp", "url": "https://bandcamp.com/{}", "category": "media"},
    {"name": "Last.fm", "url": "https://www.last.fm/user/{}", "category": "media"},
    {"name": "Mixcloud", "url": "https://www.mixcloud.com/{}/", "category": "media"},
    {"name": "Flickr", "url": "https://www.flickr.com/people/{}", "category": "media"},
    {"name": "Vimeo", "url": "https://vimeo.com/{}", "category": "media"},
    {"name": "Dailymotion", "url": "https://www.dailymotion.com/{}", "category": "media"},
    {"name": "Rumble", "url": "https://rumble.com/user/{}", "category": "media"},
    {"name": "LBRY/Odysee", "url": "https://odysee.com/@{}", "category": "media"},
    {"name": "Pexels", "url": "https://www.pexels.com/@{}", "category": "media"},
    {"name": "Unsplash", "url": "https://unsplash.com/@{}", "category": "media"},
    {"name": "500px", "url": "https://500px.com/p/{}", "category": "media"},
    {"name": "DeviantArt", "url": "https://www.deviantart.com/{}", "category": "media"},
    {"name": "ArtStation", "url": "https://www.artstation.com/{}", "category": "media"},
    {"name": "Imgur", "url": "https://imgur.com/user/{}", "category": "media"},
    {"name": "Giphy", "url": "https://giphy.com/{}", "category": "media"},
    # ═══════════════════════════════════════════
    # Gaming
    # ═══════════════════════════════════════════
    {"name": "Steam Community", "url": "https://steamcommunity.com/id/{}", "category": "gaming"},
    {"name": "Xbox Gamertag", "url": "https://xboxgamertag.com/search/{}", "category": "gaming"},
    {"name": "Roblox", "url": "https://www.roblox.com/user.aspx?username={}", "category": "gaming"},
    {"name": "Epic Games", "url": "https://store.epicgames.com/u/{}", "category": "gaming"},
    {"name": "Minecraft", "url": "https://namemc.com/profile/{}", "category": "gaming"},
    {"name": "Chess.com", "url": "https://www.chess.com/member/{}", "category": "gaming"},
    {"name": "Lichess", "url": "https://lichess.org/@/{}", "category": "gaming"},
    {"name": "Speedrun.com", "url": "https://www.speedrun.com/user/{}", "category": "gaming"},
    {"name": "Fortnite Tracker", "url": "https://fortnitetracker.com/profile/all/{}", "category": "gaming"},
    {"name": "osu!", "url": "https://osu.ppy.sh/users/{}", "category": "gaming"},
    # ═══════════════════════════════════════════
    # News / Blogging / Writing
    # ═══════════════════════════════════════════
    {"name": "Medium", "url": "https://medium.com/@{}", "category": "blogging"},
    {"name": "Blogger", "url": "https://{}.blogspot.com", "category": "blogging"},
    {"name": "WordPress", "url": "https://{}.wordpress.com", "category": "blogging"},
    {"name": "Substack", "url": "https://{}.substack.com", "category": "blogging"},
    {"name": "Ghost", "url": "https://{}.ghost.io", "category": "blogging"},
    {"name": "Wattpad", "url": "https://www.wattpad.com/user/{}", "category": "blogging"},
    {"name": "Quora", "url": "https://www.quora.com/profile/{}", "category": "blogging"},
    {"name": "HubPages", "url": "https://hubpages.com/@{}", "category": "blogging"},
    {"name": "Minds", "url": "https://www.minds.com/{}", "category": "blogging"},
    {"name": "Gab", "url": "https://gab.com/{}", "category": "blogging"},
    {"name": "Gettr", "url": "https://gettr.com/user/{}", "category": "blogging"},
    {"name": "Truth Social", "url": "https://truthsocial.com/@{}", "category": "blogging"},
    {"name": "Parler", "url": "https://parler.com/user/{}", "category": "blogging"},
    # ═══════════════════════════════════════════
    # Forums / Communities
    # ═══════════════════════════════════════════
    {"name": "Gravatar", "url": "https://en.gravatar.com/{}", "category": "other"},
    {"name": "Disqus", "url": "https://disqus.com/by/{}/", "category": "forums"},
    {"name": "ProductHunt", "url": "https://www.producthunt.com/@{}", "category": "forums"},
    {"name": "Hacker News (YC)", "url": "https://news.ycombinator.com/user?id={}", "category": "forums"},
    {"name": "Indie Hackers", "url": "https://www.indiehackers.com/{}", "category": "forums"},
    {"name": "Lobsters", "url": "https://lobste.rs/u/{}", "category": "forums"},
    {"name": "SlashDot", "url": "https://slashdot.org/~{}", "category": "forums"},
    {"name": "Discourse (Meta)", "url": "https://meta.discourse.org/u/{}", "category": "forums"},
    # ═══════════════════════════════════════════
    # Finance / Crypto
    # ═══════════════════════════════════════════
    {"name": "CoinMarketCap", "url": "https://coinmarketcap.com/community/profile/{}", "category": "finance"},
    {"name": "TradingView", "url": "https://www.tradingview.com/u/{}/", "category": "finance"},
    {"name": "Bitcointalk", "url": "https://bitcointalk.org/index.php?action=profile;u={}", "category": "finance"},
    {"name": "Etherscan (labels)", "url": "https://etherscan.io/address/{}", "category": "finance"},
    # ═══════════════════════════════════════════
    # E-commerce / Reviews
    # ═══════════════════════════════════════════
    {"name": "eBay", "url": "https://www.ebay.com/usr/{}", "category": "ecommerce"},
    {"name": "Etsy", "url": "https://www.etsy.com/shop/{}", "category": "ecommerce"},
    {"name": "Yelp", "url": "https://www.yelp.com/user_details?userid={}", "category": "ecommerce"},
    {"name": "TripAdvisor", "url": "https://www.tripadvisor.com/members/{}", "category": "ecommerce"},
    {"name": "Trustpilot", "url": "https://www.trustpilot.com/users/{}", "category": "ecommerce"},
    # ═══════════════════════════════════════════
    # Fitness / Health
    # ═══════════════════════════════════════════
    {"name": "Strava", "url": "https://www.strava.com/athletes/{}", "category": "fitness"},
    {"name": "Fitbit", "url": "https://www.fitbit.com/user/{}", "category": "fitness"},
    {"name": "MyFitnessPal", "url": "https://www.myfitnesspal.com/profile/{}", "category": "fitness"},
    # ═══════════════════════════════════════════
    # Education
    # ═══════════════════════════════════════════
    {"name": "Coursera", "url": "https://www.coursera.org/user/{}", "category": "education"},
    {"name": "Khan Academy", "url": "https://www.khanacademy.org/profile/{}", "category": "education"},
    {"name": "Duolingo", "url": "https://www.duolingo.com/profile/{}", "category": "education"},
    {"name": "Goodreads", "url": "https://www.goodreads.com/{}", "category": "education"},
    # ═══════════════════════════════════════════
    # Wish Lists / Registries
    # ═══════════════════════════════════════════
    {"name": "Wishlistr", "url": "https://www.wishlistr.com/profile/{}", "category": "other"},
    {"name": "ThingVerse", "url": "https://www.thingiverse.com/{}/designs", "category": "other"},
    {"name": "Patreon", "url": "https://www.patreon.com/{}", "category": "other"},
    {"name": "Ko-fi", "url": "https://ko-fi.com/{}", "category": "other"},
    {"name": "BuyMeACoffee", "url": "https://www.buymeacoffee.com/{}", "category": "other"},
    {"name": "Gumroad", "url": "https://gumroad.com/{}", "category": "other"},
    {"name": "Linktree", "url": "https://linktr.ee/{}", "category": "other"},
    # ═══════════════════════════════════════════
    # Photo / Video Sharing
    # ═══════════════════════════════════════════
    {"name": "VSCO", "url": "https://vsco.co/{}/gallery", "category": "media"},
    {"name": "Photobucket", "url": "https://photobucket.com/user/{}/library", "category": "media"},
    {"name": "SmugMug", "url": "https://{}.smugmug.com", "category": "media"},
    # ═══════════════════════════════════════════
    # Maps / Location
    # ═══════════════════════════════════════════
    {"name": "Google Maps Contrib", "url": "https://www.google.com/maps/contrib/{}", "category": "location"},
    {"name": "OpenStreetMap", "url": "https://www.openstreetmap.org/user/{}", "category": "location"},
    {"name": "Foursquare", "url": "https://foursquare.com/{}", "category": "location"},
    # ═══════════════════════════════════════════
    # Misc / Other
    # ═══════════════════════════════════════════
    {"name": "Gravatar", "url": "https://en.gravatar.com/{}", "category": "other"},
    {"name": "Keybase", "url": "https://keybase.io/{}", "category": "other"},
    {"name": "Archive.org", "url": "https://archive.org/details/@{}", "category": "other"},
    {"name": "Wikipedia User", "url": "https://en.wikipedia.org/wiki/User:{}", "category": "other"},
    {"name": "Instructables", "url": "https://www.instructables.com/member/{}/", "category": "other"},
    {"name": "IFTTT", "url": "https://ifttt.com/p/{}", "category": "other"},
    {"name": "Trello", "url": "https://trello.com/{}", "category": "other"},
    {"name": "Letterboxd", "url": "https://letterboxd.com/{}/", "category": "other"},
    {"name": "MyAnimeList", "url": "https://myanimelist.net/profile/{}", "category": "other"},
    {"name": "AniList", "url": "https://anilist.co/user/{}", "category": "other"},
    {"name": "Spotify Podcasters", "url": "https://podcasters.spotify.com/pod/show/{}", "category": "media"},
    {"name": "Carrd", "url": "https://{}.carrd.co", "category": "other"},
    {"name": "Notion", "url": "https://notion.so/{}", "category": "other"},
    # ═══════════════════════════════════════════
    # Irish / EU specific
    # ═══════════════════════════════════════════
    {"name": "Boards.ie", "url": "https://www.boards.ie/member/{}", "category": "irish"},
    {"name": "Adverts.ie", "url": "https://www.adverts.ie/seller/{}", "category": "irish"},
    {"name": "DoneDeal", "url": "https://www.donedeal.ie/seller/{}", "category": "irish"},
]


class UsernameModule(BaseOSINTModule):
    """Search for a username across multiple social platforms."""

    name = "Username Search"
    description = "Search a username across 200+ social platforms and websites (Sherlock-like)"
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
