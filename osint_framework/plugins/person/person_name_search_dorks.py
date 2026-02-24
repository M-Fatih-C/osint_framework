from typing import Any, Dict, List
from urllib.parse import quote_plus

from osint_framework.plugins.base import BaseModule
from osint_framework.plugins.person.person_name_utils import build_name_analysis


class PersonNameSearchDorksModule(BaseModule):
    name = "Person_Name_Search_Dorks"
    version = "1.0.0"
    description = "Builds search-engine dorks and platform-focused queries for a full name."
    target_types = ["person_name"]
    author = "OSINT_Framework_Team"

    _ENGINES = {
        "google": "https://www.google.com/search?q={}",
        "bing": "https://www.bing.com/search?q={}",
        "duckduckgo": "https://duckduckgo.com/?q={}",
        "yandex": "https://yandex.com/search/?text={}",
    }

    async def run(self, target: str) -> Dict[str, Any]:
        info = build_name_analysis(target)
        normalized = info["normalized"]
        ascii_name = info["ascii_transliteration"]

        query_specs: List[Dict[str, str]] = [
            {"label": "Exact name", "query": f"\"{normalized}\""},
            {"label": "LinkedIn profiles", "query": f"\"{normalized}\" site:linkedin.com/in"},
            {"label": "GitHub profiles", "query": f"\"{normalized}\" site:github.com"},
            {"label": "X/Twitter profiles", "query": f"\"{normalized}\" (site:x.com OR site:twitter.com)"},
            {"label": "Instagram profiles", "query": f"\"{normalized}\" site:instagram.com"},
            {"label": "Facebook profiles", "query": f"\"{normalized}\" site:facebook.com"},
            {"label": "TikTok profiles", "query": f"\"{normalized}\" site:tiktok.com"},
            {"label": "YouTube mentions", "query": f"\"{normalized}\" site:youtube.com"},
            {"label": "PDF documents", "query": f"\"{normalized}\" filetype:pdf"},
            {"label": "Resume/CV", "query": f"\"{normalized}\" (resume OR cv)"},
            {"label": "Email mentions", "query": f"\"{normalized}\" (\"@gmail.com\" OR \"@hotmail.com\" OR \"@outlook.com\")"},
        ]

        if ascii_name and ascii_name.lower() != normalized.lower():
            query_specs.append(
                {"label": "ASCII transliteration exact", "query": f"\"{ascii_name}\""}
            )

        search_urls = {
            engine: [
                {"label": item["label"], "url": template.format(quote_plus(item["query"]))}
                for item in query_specs
            ]
            for engine, template in self._ENGINES.items()
        }

        quick_links = []
        for item in query_specs[:5]:
            quick_links.append(
                {
                    "label": item["label"],
                    "google": self._ENGINES["google"].format(quote_plus(item["query"])),
                    "bing": self._ENGINES["bing"].format(quote_plus(item["query"])),
                }
            )

        return {
            "target_person_name": target,
            "normalized_name": normalized,
            "ascii_transliteration": ascii_name,
            "queries_total": len(query_specs),
            "queries": query_specs,
            "quick_links": quick_links,
            "search_urls": search_urls,
            "notes": [
                "Prefer exact-quote queries first, then widen with platform filters.",
                "Try both native and ASCII transliterated forms for Turkish names.",
            ],
        }
