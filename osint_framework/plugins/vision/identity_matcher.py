from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse


class VisionIdentityMatcher:
    """
    Correlates reverse-image hits + scraped entities into identity candidates.

    This matcher is intentionally heuristic and deterministic:
    - no external API calls
    - stable scoring rules
    - compact, explainable output for UI/report consumers
    """

    _NAME_WS_RE = re.compile(r"\s+")
    _PROFILE_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
        (re.compile(r"^(?:www\.)?github\.com$", re.IGNORECASE), "github"),
        (re.compile(r"^(?:www\.)?(?:x\.com|twitter\.com)$", re.IGNORECASE), "x"),
        (re.compile(r"^(?:[a-z]+\.)?linkedin\.com$", re.IGNORECASE), "linkedin"),
        (re.compile(r"^(?:www\.)?instagram\.com$", re.IGNORECASE), "instagram"),
        (re.compile(r"^(?:www\.)?facebook\.com$", re.IGNORECASE), "facebook"),
        (re.compile(r"^(?:www\.)?tiktok\.com$", re.IGNORECASE), "tiktok"),
        (re.compile(r"^(?:www\.)?youtube\.com$", re.IGNORECASE), "youtube"),
    )
    _RESERVED_PATH_SEGMENTS = {
        "",
        "home",
        "about",
        "explore",
        "search",
        "login",
        "signup",
        "watch",
        "feed",
        "privacy",
        "tos",
        "settings",
        "help",
        "jobs",
        "company",
        "groups",
        "events",
        "messages",
        "notifications",
        "photos",
        "videos",
        "posts",
        "status",
        "share",
        "p",
        "reel",
        "reels",
        "tv",
    }
    _SOCIAL_PLATFORMS = {"github", "x", "linkedin", "instagram", "facebook", "tiktok", "youtube"}

    def __init__(self, *, max_candidates: int = 5, min_confidence: float = 0.35):
        self.max_candidates = max(1, int(max_candidates))
        self.min_confidence = max(0.0, min(1.0, float(min_confidence)))

    def match(
        self,
        *,
        image_target: str,
        reverse_search: Dict[str, Any],
        scraped: Dict[str, Any],
        similarity: Dict[str, Any],
    ) -> Dict[str, Any]:
        reverse_hits = (reverse_search.get("results") if isinstance(reverse_search, dict) else []) or []
        pages = (scraped.get("pages") if isinstance(scraped, dict) else []) or []
        entities = (scraped.get("entities") if isinstance(scraped, dict) else []) or []
        similarity_total = int(
            (similarity.get("matches_total") if isinstance(similarity, dict) else 0) or 0
        )

        page_index = self._build_page_index(pages)
        candidates: Dict[str, Dict[str, Any]] = {}
        url_to_candidate: Dict[str, str] = {}

        # 1) Start from reverse-image hits: strongest identity pivot for this pipeline.
        for hit in reverse_hits[:400]:
            if not isinstance(hit, dict):
                continue
            url = hit.get("url")
            if not isinstance(url, str) or not url.startswith(("http://", "https://")):
                continue

            profile = self._extract_social_profile(url)
            if not profile:
                continue

            canonical_url = self._canonical_url(url)
            key = self._candidate_key_for_username(profile["platform"], profile["username"])
            candidate = self._get_or_create_candidate(
                candidates, key, display_name=profile["username"]
            )
            self._attach_profile(
                candidate,
                url=canonical_url,
                platform=profile["platform"],
                username=profile["username"],
                title=hit.get("title") or (page_index.get(canonical_url) or {}).get("title"),
                source="reverse_image",
                match_type=hit.get("match_type"),
            )
            url_to_candidate[canonical_url] = key

        # 2) Add scraped pages (including social profile pages not returned by reverse stage).
        for page in pages[:200]:
            if not isinstance(page, dict):
                continue
            page_url = page.get("final_url") or page.get("url")
            if not isinstance(page_url, str):
                continue
            profile = self._extract_social_profile(page_url)
            if not profile:
                continue

            canonical_url = self._canonical_url(page_url)
            key = url_to_candidate.get(canonical_url) or self._candidate_key_for_username(
                profile["platform"], profile["username"]
            )
            candidate = self._get_or_create_candidate(
                candidates, key, display_name=profile["username"]
            )
            self._attach_profile(
                candidate,
                url=canonical_url,
                platform=profile["platform"],
                username=profile["username"],
                title=page.get("title"),
                source="scraped_page",
                match_type="page_profile",
            )
            url_to_candidate[canonical_url] = key

        # 3) Fuse extracted entities into candidates.
        for ent in entities[:800]:
            if not isinstance(ent, dict):
                continue
            etype = str(ent.get("type") or "").strip().lower()
            value = ent.get("value")
            if not etype or not isinstance(value, str) or not value.strip():
                continue
            raw_source_url = ent.get("source_url")
            source_url = self._canonical_url(raw_source_url) if isinstance(raw_source_url, str) else None

            key = self._resolve_candidate_key_from_entity(ent, source_url, url_to_candidate)
            if not key:
                continue
            candidate = self._get_or_create_candidate(candidates, key, display_name=value)

            if source_url:
                candidate["evidence_urls"].add(source_url)
                profile = self._extract_social_profile(source_url)
                if profile:
                    self._attach_profile(
                        candidate,
                        url=source_url,
                        platform=profile["platform"],
                        username=profile["username"],
                        title=(page_index.get(source_url) or {}).get("title"),
                        source="entity_source",
                        match_type="entity_mention",
                    )
                    url_to_candidate[source_url] = key

            if etype == "person_name":
                candidate["person_names"].add(self._clean_person_name(value))
                candidate["reasons"].add("name_detected")
            elif etype == "username":
                platform = str(ent.get("platform") or "").strip().lower() or None
                if not platform and source_url:
                    parsed = self._extract_social_profile(source_url)
                    if parsed:
                        platform = parsed["platform"]
                if not platform:
                    platform = "unknown"
                candidate["usernames"].setdefault(platform, set()).add(value.strip())
                candidate["reasons"].add("username_detected")
            elif etype == "email":
                candidate["emails"].add(value.strip().lower())
                candidate["reasons"].add("email_detected")
            elif etype == "domain":
                candidate["domains"].add(value.strip().lower())
            elif etype == "url":
                parsed_url = self._extract_social_profile(value)
                if parsed_url:
                    self._attach_profile(
                        candidate,
                        url=self._canonical_url(value),
                        platform=parsed_url["platform"],
                        username=parsed_url["username"],
                        title=(page_index.get(self._canonical_url(value)) or {}).get("title"),
                        source="entity_url",
                        match_type="entity_profile",
                    )
                    candidate["reasons"].add("social_profile_detected")

        candidate_payloads = self._build_candidate_payloads(
            candidates=candidates,
            similarity_total=similarity_total,
            image_target=image_target,
        )

        social_profiles = self._build_social_profile_index(candidate_payloads)
        if not candidate_payloads:
            return {
                "status": "no_matches",
                "signals": {
                    "reverse_results_total": len(reverse_hits),
                    "entities_total": len(entities),
                    "similarity_matches_total": similarity_total,
                },
                "social_profiles_total": len(social_profiles),
                "social_profiles": social_profiles[:30],
                "candidates_total": 0,
                "candidates": [],
                "best_candidate": None,
            }

        return {
            "status": "ok",
            "signals": {
                "reverse_results_total": len(reverse_hits),
                "entities_total": len(entities),
                "similarity_matches_total": similarity_total,
            },
            "social_profiles_total": len(social_profiles),
            "social_profiles": social_profiles[:30],
            "candidates_total": len(candidate_payloads),
            "candidates": candidate_payloads[: self.max_candidates],
            "best_candidate": candidate_payloads[0],
        }

    def _build_page_index(self, pages: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        index: Dict[str, Dict[str, Any]] = {}
        for page in pages:
            if not isinstance(page, dict):
                continue
            url = page.get("final_url") or page.get("url")
            if not isinstance(url, str) or not url.startswith(("http://", "https://")):
                continue
            index[self._canonical_url(url)] = page
        return index

    def _resolve_candidate_key_from_entity(
        self,
        entity: Dict[str, Any],
        source_url: Optional[str],
        url_to_candidate: Dict[str, str],
    ) -> Optional[str]:
        etype = str(entity.get("type") or "").strip().lower()
        value = str(entity.get("value") or "").strip()
        if not value:
            return None

        if source_url and source_url in url_to_candidate:
            return url_to_candidate[source_url]

        if etype == "username":
            platform = str(entity.get("platform") or "").strip().lower()
            if not platform and source_url:
                profile = self._extract_social_profile(source_url)
                if profile:
                    platform = profile["platform"]
            if not platform:
                platform = "unknown"
            return self._candidate_key_for_username(platform, value)

        if etype == "person_name":
            return self._candidate_key_for_name(value)

        if source_url:
            profile = self._extract_social_profile(source_url)
            if profile:
                return self._candidate_key_for_username(profile["platform"], profile["username"])

        if etype in {"email", "domain", "url"}:
            return "global_candidate"
        return None

    def _candidate_key_for_username(self, platform: str, username: str) -> str:
        clean_platform = (platform or "unknown").strip().lower()
        clean_username = (username or "").strip().lower()
        return f"u:{clean_platform}:{clean_username}"

    def _candidate_key_for_name(self, name: str) -> str:
        clean = self._clean_person_name(name).lower()
        return f"n:{clean}"

    def _get_or_create_candidate(
        self,
        candidates: Dict[str, Dict[str, Any]],
        key: str,
        *,
        display_name: str,
    ) -> Dict[str, Any]:
        if key in candidates:
            return candidates[key]

        candidates[key] = {
            "candidate_key": key,
            "display_name": display_name.strip(),
            "person_names": set(),
            "usernames": {},
            "emails": set(),
            "domains": set(),
            "profiles": {},
            "evidence_urls": set(),
            "reasons": set(),
        }
        return candidates[key]

    def _attach_profile(
        self,
        candidate: Dict[str, Any],
        *,
        url: str,
        platform: str,
        username: str,
        title: Any,
        source: str,
        match_type: Any,
    ) -> None:
        if not url:
            return
        profile = candidate["profiles"].setdefault(
            url,
            {
                "url": url,
                "platform": platform,
                "username": username,
                "title": "",
                "sources": [],
                "match_types": [],
            },
        )
        if isinstance(title, str) and title.strip() and not profile.get("title"):
            profile["title"] = title.strip()
        if source and source not in profile["sources"]:
            profile["sources"].append(source)
        if isinstance(match_type, str) and match_type and match_type not in profile["match_types"]:
            profile["match_types"].append(match_type)

        candidate["evidence_urls"].add(url)
        candidate["usernames"].setdefault(platform, set()).add(username)
        candidate["domains"].add(urlparse(url).hostname or "")
        candidate["reasons"].add("social_profile_detected")

    def _build_candidate_payloads(
        self,
        *,
        candidates: Dict[str, Dict[str, Any]],
        similarity_total: int,
        image_target: str,
    ) -> List[Dict[str, Any]]:
        scored: List[Dict[str, Any]] = []
        for raw in candidates.values():
            usernames_flat = [
                {"platform": platform, "value": username}
                for platform, usernames in raw["usernames"].items()
                for username in sorted(usernames)
            ]
            usernames_flat.sort(key=lambda x: (x["platform"], x["value"]))

            domains = sorted([d for d in raw["domains"] if d])
            person_names = sorted([n for n in raw["person_names"] if n])
            emails = sorted([e for e in raw["emails"] if e])
            profiles = list(raw["profiles"].values())
            profiles.sort(key=lambda p: p.get("url") or "")

            score = self._score_candidate(
                profile_count=len(profiles),
                username_count=len(usernames_flat),
                person_name_count=len(person_names),
                email_count=len(emails),
                evidence_count=len(raw["evidence_urls"]),
                social_platforms={item["platform"] for item in usernames_flat},
                similarity_total=similarity_total,
            )
            if score < self.min_confidence:
                continue

            display_name = raw.get("display_name") or ""
            if person_names:
                display_name = person_names[0]
            elif usernames_flat:
                display_name = usernames_flat[0]["value"]
            elif not display_name:
                display_name = "Unknown Candidate"

            scored.append(
                {
                    "candidate_id": f"idm_{len(scored) + 1}",
                    "candidate_key": raw.get("candidate_key"),
                    "display_name": display_name,
                    "image_target": image_target,
                    "confidence_score": round(score, 4),
                    "confidence_level": self._confidence_level(score),
                    "person_names": person_names[:10],
                    "usernames": usernames_flat[:25],
                    "emails": emails[:10],
                    "domains": domains[:20],
                    "profiles": profiles[:25],
                    "evidence_count": len(raw["evidence_urls"]),
                    "evidence_urls": sorted(raw["evidence_urls"])[:30],
                    "reasons": sorted(raw["reasons"]),
                }
            )

        scored.sort(
            key=lambda item: (
                float(item.get("confidence_score") or 0.0),
                int(item.get("evidence_count") or 0),
                len(item.get("profiles") or []),
            ),
            reverse=True,
        )
        for idx, item in enumerate(scored, start=1):
            item["candidate_id"] = f"idm_{idx}"
        return scored

    def _score_candidate(
        self,
        *,
        profile_count: int,
        username_count: int,
        person_name_count: int,
        email_count: int,
        evidence_count: int,
        social_platforms: Set[str],
        similarity_total: int,
    ) -> float:
        score = 0.0
        score += min(profile_count, 3) * 0.14
        score += min(username_count, 4) * 0.09
        score += min(person_name_count, 2) * 0.17
        score += min(email_count, 2) * 0.08

        if evidence_count >= 2:
            score += 0.08
        if evidence_count >= 4:
            score += 0.05

        if social_platforms.intersection(self._SOCIAL_PLATFORMS):
            score += 0.05

        if similarity_total > 0 and (profile_count > 0 or username_count > 0):
            score += 0.12

        return max(0.0, min(0.98, score))

    def _build_social_profile_index(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        output: List[Dict[str, Any]] = []
        for cand in candidates:
            for profile in cand.get("profiles") or []:
                url = profile.get("url")
                if not isinstance(url, str):
                    continue
                key = url.strip().lower()
                if key in seen:
                    continue
                seen.add(key)
                output.append(
                    {
                        "url": url,
                        "platform": profile.get("platform"),
                        "username": profile.get("username"),
                        "title": profile.get("title"),
                        "candidate_id": cand.get("candidate_id"),
                        "candidate_name": cand.get("display_name"),
                    }
                )
        return output

    def _confidence_level(self, score: float) -> str:
        if score >= 0.75:
            return "high"
        if score >= 0.5:
            return "medium"
        return "low"

    def _extract_social_profile(self, url: str) -> Optional[Dict[str, str]]:
        try:
            parsed = urlparse(url)
        except Exception:
            return None
        host = (parsed.hostname or "").strip().lower()
        if not host:
            return None

        platform = None
        for pattern, candidate_platform in self._PROFILE_PATTERNS:
            if pattern.match(host):
                platform = candidate_platform
                break
        if not platform:
            return None

        path_segments = [segment.strip() for segment in parsed.path.split("/") if segment.strip()]
        username = self._extract_username(platform, path_segments)
        if not username:
            return None

        return {"platform": platform, "username": username}

    def _extract_username(self, platform: str, segments: List[str]) -> Optional[str]:
        if not segments:
            return None

        segment = segments[0]
        if platform == "linkedin":
            if segment in {"in", "pub"} and len(segments) >= 2:
                segment = segments[1]
            elif segment not in {"company", "school"}:
                return None
            else:
                return None
        elif platform == "youtube":
            if segment.startswith("@"):
                segment = segment[1:]
            elif segment in {"channel", "user", "c"} and len(segments) >= 2:
                segment = segments[1]
            else:
                return None
        elif platform == "tiktok":
            if segment.startswith("@"):
                segment = segment[1:]
        elif platform == "facebook":
            if segment == "profile.php":
                return None

        clean = segment.strip().strip("/")
        if not clean:
            return None
        lower = clean.lower()
        if lower in self._RESERVED_PATH_SEGMENTS:
            return None
        if any(ch.isspace() for ch in clean):
            return None
        return clean

    def _canonical_url(self, value: str) -> str:
        parsed = urlparse(value.strip())
        scheme = parsed.scheme.lower() or "https"
        netloc = parsed.netloc.lower()
        path = parsed.path or "/"
        if path != "/":
            path = path.rstrip("/") or "/"
        return f"{scheme}://{netloc}{path}"

    def _clean_person_name(self, value: str) -> str:
        return self._NAME_WS_RE.sub(" ", value.strip())
