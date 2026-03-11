from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse


class VisionOsintScraper:
    """Lightweight page scraper and entity extractor for reverse-image result URLs."""

    _TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
    _TAG_RE = re.compile(r"<[^>]+>")
    _WS_RE = re.compile(r"\s+")
    _EMAIL_RE = re.compile(r"[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9-.]+")

    _PROFILE_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
        (re.compile(r"https?://(?:www\.)?github\.com/([^/?#]+)", re.IGNORECASE), "github"),
        (re.compile(r"https?://(?:www\.)?(?:x\.com|twitter\.com)/([^/?#]+)", re.IGNORECASE), "x"),
        (re.compile(r"https?://(?:[a-z]+\.)?linkedin\.com/in/([^/?#]+)", re.IGNORECASE), "linkedin"),
        (re.compile(r"https?://(?:www\.)?instagram\.com/([^/?#]+)", re.IGNORECASE), "instagram"),
        (re.compile(r"https?://(?:www\.)?facebook\.com/([^/?#]+)", re.IGNORECASE), "facebook"),
    )

    async def scrape(self, module, urls: List[str], max_pages: int = 8) -> Dict[str, Any]:
        unique_urls = []
        seen = set()
        for url in urls:
            if not isinstance(url, str) or not url.startswith(("http://", "https://")):
                continue
            key = url.strip().lower()
            if key in seen:
                continue
            seen.add(key)
            unique_urls.append(url.strip())

        selected = unique_urls[: max(1, int(max_pages))]
        pages: List[Dict[str, Any]] = []
        entities: List[Dict[str, Any]] = []

        for url in selected:
            page = await self._fetch_page(module, url)
            pages.append(page)
            entities.extend(self._extract_entities(url, page))

        dedup_entities: Dict[str, Dict[str, Any]] = {}
        for ent in entities:
            key = f"{ent.get('type')}::{str(ent.get('value', '')).lower()}::{ent.get('source_url')}"
            if key not in dedup_entities:
                dedup_entities[key] = ent

        return {
            "pages": pages,
            "entities": list(dedup_entities.values()),
            "pages_scraped": len(pages),
            "entities_total": len(dedup_entities),
        }

    async def _fetch_page(self, module, url: str) -> Dict[str, Any]:
        async with module.get_client() as client:
            try:
                resp = await client.get(url, timeout=module.timeout, follow_redirects=True)
            except Exception as exc:
                return {
                    "url": url,
                    "status_code": None,
                    "title": None,
                    "final_url": url,
                    "error": str(exc),
                    "snippet": "",
                }

        text = resp.text or ""
        title = self._extract_title(text)
        snippet = self._extract_snippet(text)
        return {
            "url": url,
            "status_code": resp.status_code,
            "title": title,
            "final_url": str(resp.url),
            "error": None,
            "snippet": snippet,
        }

    def _extract_title(self, text: str) -> str:
        if not text:
            return ""

        try:
            from bs4 import BeautifulSoup  # type: ignore

            soup = BeautifulSoup(text, "html.parser")
            if soup.title and soup.title.string:
                return self._clean_text(soup.title.string)
        except Exception:
            pass

        match = self._TITLE_RE.search(text)
        if not match:
            return ""
        return self._clean_text(match.group(1))

    def _extract_snippet(self, text: str, limit: int = 260) -> str:
        if not text:
            return ""
        plain = self._clean_text(self._TAG_RE.sub(" ", text))
        if len(plain) <= limit:
            return plain
        return plain[: limit - 3] + "..."

    def _extract_entities(self, url: str, page: Dict[str, Any]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        title = str(page.get("title") or "")
        snippet = str(page.get("snippet") or "")

        # Profile URL derived usernames
        for pattern, platform in self._PROFILE_PATTERNS:
            m = pattern.search(url)
            if not m:
                continue
            username = m.group(1).strip("/ ")
            if username:
                out.append(
                    {
                        "type": "username",
                        "value": username,
                        "platform": platform,
                        "source_url": url,
                    }
                )

        # Candidate name from title split heuristics
        for part in re.split(r"[|\-•]", title):
            cleaned = self._clean_text(part)
            if 3 <= len(cleaned) <= 80 and re.match(r"^[A-Za-zÀ-ÖØ-öø-ÿ' .]{3,80}$", cleaned):
                words = cleaned.split()
                if 2 <= len(words) <= 5:
                    out.append(
                        {
                            "type": "person_name",
                            "value": cleaned,
                            "source_url": url,
                        }
                    )
                    break

        for email in self._EMAIL_RE.findall(snippet):
            out.append({"type": "email", "value": email, "source_url": url})

        parsed = urlparse(url)
        host = (parsed.hostname or "").strip()
        if host:
            out.append({"type": "domain", "value": host, "source_url": url})

        return out

    def _clean_text(self, text: str) -> str:
        return self._WS_RE.sub(" ", (text or "").strip())
