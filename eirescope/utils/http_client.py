"""HTTP client with retries, rate limiting, and user-agent rotation for OSINT."""
import time
import random
import logging
import requests
from typing import Optional, Dict, Any

logger = logging.getLogger("eirescope.http")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
]


class OSINTHTTPClient:
    """HTTP client optimized for OSINT data collection."""

    def __init__(self, timeout: int = 10, max_retries: int = 3,
                 rate_limit: float = 0.5, proxy: str = None):
        self.timeout = timeout
        self.max_retries = max_retries
        self.rate_limit = rate_limit
        self.session = requests.Session()
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        self._last_request_time = 0

    def _get_headers(self, extra_headers: Dict = None) -> Dict:
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "DNT": "1",
            "Connection": "keep-alive",
        }
        if extra_headers:
            headers.update(extra_headers)
        return headers

    def _rate_limit_wait(self):
        elapsed = time.time() - self._last_request_time
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self._last_request_time = time.time()

    def get(self, url: str, headers: Dict = None, params: Dict = None,
            allow_redirects: bool = True, **kwargs) -> Optional[requests.Response]:
        return self._request("GET", url, headers=headers, params=params,
                             allow_redirects=allow_redirects, **kwargs)

    def head(self, url: str, headers: Dict = None,
             allow_redirects: bool = True, **kwargs) -> Optional[requests.Response]:
        return self._request("HEAD", url, headers=headers,
                             allow_redirects=allow_redirects, **kwargs)

    def post(self, url: str, headers: Dict = None, data: Any = None,
             json: Any = None, **kwargs) -> Optional[requests.Response]:
        return self._request("POST", url, headers=headers, data=data,
                             json=json, **kwargs)

    def _request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        extra_headers = kwargs.pop("headers", None)
        kwargs["headers"] = self._get_headers(extra_headers)
        kwargs.setdefault("timeout", self.timeout)

        for attempt in range(self.max_retries):
            try:
                self._rate_limit_wait()
                response = self.session.request(method, url, **kwargs)
                return response
            except requests.exceptions.Timeout:
                logger.warning(f"Timeout on {method} {url} (attempt {attempt + 1})")
            except requests.exceptions.ConnectionError:
                logger.warning(f"Connection error on {method} {url} (attempt {attempt + 1})")
            except requests.exceptions.RequestException as e:
                logger.error(f"Request error on {method} {url}: {e}")
                return None

            if attempt < self.max_retries - 1:
                backoff = (2 ** attempt) + random.uniform(0, 1)
                time.sleep(backoff)

        logger.error(f"All {self.max_retries} retries failed for {method} {url}")
        return None

    def check_url_exists(self, url: str, timeout: int = 5) -> bool:
        """Quick check if a URL returns a successful response."""
        try:
            self._rate_limit_wait()
            resp = self.session.get(
                url,
                headers=self._get_headers(),
                timeout=timeout,
                allow_redirects=True,
                stream=True,
            )
            resp.close()
            return resp.status_code == 200
        except Exception:
            return False
