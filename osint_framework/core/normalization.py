import ipaddress
import re
from datetime import datetime, UTC
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse


EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
DOMAIN_RE = re.compile(
    r"(?<!@)\b(?=.{1,253}\b)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\b"
)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class IntelNormalizer:
    """
    Builds a normalized intelligence graph from heterogeneous module outputs.

    Output is JSON-serializable and intentionally conservative: only a small set of
    entity/relation types is emitted until providers are fully standardized.
    """

    def __init__(self):
        self._entities: Dict[str, Dict[str, Any]] = {}
        self._relations: List[Dict[str, Any]] = []
        self._relation_keys: Set[Tuple[str, str, str]] = set()
        self._evidence: List[Dict[str, Any]] = []
        self._evidence_keys: Set[Tuple[str, str, str]] = set()
        self._entity_seq = 0
        self._evidence_seq = 0
        self._source_modules: Set[str] = set()

    @classmethod
    def build(
        cls,
        results: List[Dict[str, Any]],
        *,
        target: Optional[str] = None,
        target_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        builder = cls()
        return builder._build(results, target=target, target_type=target_type)

    def _build(
        self,
        results: List[Dict[str, Any]],
        *,
        target: Optional[str] = None,
        target_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        root_entity_id: Optional[str] = None
        if target and target_type:
            root_entity_id = self.add_entity(
                target_type, target, display=target, confidence=1.0, source_module="__root__"
            )

        for result in results or []:
            module_name = str(result.get("module") or "Unknown")
            data = result.get("data") if isinstance(result.get("data"), dict) else {}
            self._source_modules.add(module_name)

            module_evidence_id = self.add_evidence(
                module_name,
                kind="module_result",
                value=f"module:{module_name}",
                summary=self._module_summary(data),
            )

            if root_entity_id:
                self._add_module_specific_entities(
                    module_name, data, root_entity_id=root_entity_id, evidence_id=module_evidence_id
                )

            self._extract_generic_indicators(
                module_name, data, root_entity_id=root_entity_id, evidence_id=module_evidence_id
            )

        entities = sorted(self._entities.values(), key=lambda e: (e["type"], e["value"]))
        relations = sorted(
            self._relations,
            key=lambda r: (r["type"], r["from_entity_id"], r["to_entity_id"]),
        )
        evidence = sorted(self._evidence, key=lambda ev: ev["id"])

        type_counts: Dict[str, int] = {}
        for entity in entities:
            et = entity["type"]
            type_counts[et] = type_counts.get(et, 0) + 1

        return {
            "schema_version": "1.0",
            "generated_at": datetime.now(UTC).isoformat(),
            "target": {"value": target, "type": target_type} if target else None,
            "entities": entities,
            "relations": relations,
            "evidence": evidence,
            "source_modules": sorted(self._source_modules),
            "stats": {
                "entities_total": len(entities),
                "relations_total": len(relations),
                "evidence_total": len(evidence),
                "entity_types": type_counts,
            },
        }

    def add_entity(
        self,
        entity_type: str,
        value: str,
        *,
        display: Optional[str] = None,
        source_module: Optional[str] = None,
        confidence: float = 0.5,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> str:
        value = str(value).strip()
        if not value:
            raise ValueError("entity value cannot be empty")

        key = f"{entity_type}:{self._canonicalize(entity_type, value)}"
        existing = self._entities.get(key)
        if existing:
            if source_module and source_module not in existing["sources"]:
                existing["sources"].append(source_module)
            existing["confidence"] = max(existing.get("confidence", 0.0), float(confidence))
            if attributes:
                merged = dict(existing.get("attributes") or {})
                for attr_key, attr_val in attributes.items():
                    if attr_val is None:
                        continue
                    if attr_key not in merged:
                        merged[attr_key] = attr_val
                existing["attributes"] = merged or None
            return existing["id"]

        self._entity_seq += 1
        entity_id = f"ent_{self._entity_seq:05d}"
        payload = {
            "id": entity_id,
            "type": entity_type,
            "value": value,
            "display": display or value,
            "confidence": float(confidence),
            "sources": [source_module] if source_module else [],
            "attributes": attributes or None,
        }
        self._entities[key] = payload
        return entity_id

    def add_relation(
        self,
        relation_type: str,
        from_entity_id: str,
        to_entity_id: str,
        *,
        source_module: Optional[str] = None,
        confidence: float = 0.5,
        evidence_id: Optional[str] = None,
    ) -> None:
        if from_entity_id == to_entity_id:
            return
        key = (relation_type, from_entity_id, to_entity_id)
        if key in self._relation_keys:
            return
        self._relation_keys.add(key)
        self._relations.append(
            {
                "id": f"rel_{len(self._relations) + 1:05d}",
                "type": relation_type,
                "from_entity_id": from_entity_id,
                "to_entity_id": to_entity_id,
                "confidence": float(confidence),
                "source_module": source_module,
                "evidence_id": evidence_id,
            }
        )

    def add_evidence(
        self,
        module_name: str,
        *,
        kind: str,
        value: str,
        summary: Optional[str] = None,
        url: Optional[str] = None,
    ) -> str:
        key = (module_name, kind, value)
        for item in self._evidence:
            if (item["source_module"], item["kind"], item["value"]) == key:
                return item["id"]

        self._evidence_seq += 1
        evidence_id = f"ev_{self._evidence_seq:05d}"
        payload = {
            "id": evidence_id,
            "source_module": module_name,
            "kind": kind,
            "value": value,
            "summary": summary,
            "url": url,
        }
        self._evidence.append(payload)
        return evidence_id

    def _add_module_specific_entities(
        self,
        module_name: str,
        data: Dict[str, Any],
        *,
        root_entity_id: str,
        evidence_id: str,
    ) -> None:
        if module_name == "Username_Checker":
            username = data.get("target_username")
            if isinstance(username, str) and username.strip():
                username_id = self.add_entity(
                    "username",
                    username,
                    source_module=module_name,
                    confidence=0.95,
                )
                self.add_relation(
                    "investigated_as",
                    root_entity_id,
                    username_id,
                    source_module=module_name,
                    confidence=0.95,
                    evidence_id=evidence_id,
                )

                for profile in data.get("profiles") or []:
                    if not isinstance(profile, dict):
                        continue
                    profile_url = profile.get("url")
                    if not isinstance(profile_url, str):
                        continue
                    url_entity_id = self.add_entity(
                        "url",
                        profile_url,
                        source_module=module_name,
                        confidence=0.9,
                        attributes={
                            "site": profile.get("site"),
                            "http_status": profile.get("http_status"),
                        },
                    )
                    self.add_relation(
                        "has_profile",
                        username_id,
                        url_entity_id,
                        source_module=module_name,
                        confidence=0.9,
                        evidence_id=evidence_id,
                    )
                    self._link_url_domain(
                        profile_url, source_module=module_name, evidence_id=evidence_id
                    )
            return

        if module_name == "Person_Name_Handle_Generator":
            person_name = data.get("target_person_name")
            if isinstance(person_name, str) and person_name.strip():
                person_id = self.add_entity(
                    "person_name",
                    person_name,
                    source_module=module_name,
                    confidence=0.95,
                    attributes={"normalized_name": data.get("normalized_name")},
                )
                self.add_relation(
                    "investigated_as",
                    root_entity_id,
                    person_id,
                    source_module=module_name,
                    confidence=0.95,
                    evidence_id=evidence_id,
                )

                for username in (
                    (((data.get("username_candidates") or {}).get("conservative")) or [])[:20]
                ):
                    if not isinstance(username, str):
                        continue
                    username_id = self.add_entity(
                        "username_candidate",
                        username,
                        source_module=module_name,
                        confidence=0.6,
                    )
                    self.add_relation(
                        "candidate_username_for",
                        person_id,
                        username_id,
                        source_module=module_name,
                        confidence=0.6,
                        evidence_id=evidence_id,
                    )

                for local_part in (data.get("email_local_part_candidates") or [])[:20]:
                    if not isinstance(local_part, str):
                        continue
                    local_id = self.add_entity(
                        "email_local_part_candidate",
                        local_part,
                        source_module=module_name,
                        confidence=0.55,
                    )
                    self.add_relation(
                        "candidate_email_local_part_for",
                        person_id,
                        local_id,
                        source_module=module_name,
                        confidence=0.55,
                        evidence_id=evidence_id,
                    )
            return

        if module_name == "Person_Name_Analyzer":
            person_name = data.get("target_person_name")
            if isinstance(person_name, str) and person_name.strip():
                person_id = self.add_entity(
                    "person_name",
                    person_name,
                    source_module=module_name,
                    confidence=0.95,
                    attributes={
                        "normalized_name": data.get("normalized_name"),
                        "ascii_transliteration": data.get("ascii_transliteration"),
                        "initials": data.get("initials"),
                    },
                )
                self.add_relation(
                    "investigated_as",
                    root_entity_id,
                    person_id,
                    source_module=module_name,
                    confidence=0.95,
                    evidence_id=evidence_id,
                )
            return

        if module_name == "Person_Name_Search_Dorks":
            person_name = data.get("target_person_name")
            if isinstance(person_name, str) and person_name.strip():
                person_id = self.add_entity(
                    "person_name",
                    person_name,
                    source_module=module_name,
                    confidence=0.9,
                )
                self.add_relation(
                    "investigated_as",
                    root_entity_id,
                    person_id,
                    source_module=module_name,
                    confidence=0.9,
                    evidence_id=evidence_id,
                )
                for quick in (data.get("quick_links") or [])[:15]:
                    if not isinstance(quick, dict):
                        continue
                    for engine in ("google", "bing"):
                        url = quick.get(engine)
                        if not isinstance(url, str):
                            continue
                        url_id = self.add_entity(
                            "search_url",
                            url,
                            source_module=module_name,
                            confidence=0.7,
                            attributes={"engine": engine, "label": quick.get("label")},
                        )
                        self.add_relation(
                            "search_query_for",
                            person_id,
                            url_id,
                            source_module=module_name,
                            confidence=0.7,
                            evidence_id=evidence_id,
                        )
                        self._link_url_domain(url, source_module=module_name, evidence_id=evidence_id)
            return

        if module_name == "Vision_Image_OSINT":
            image_target = data.get("image_path") or data.get("image_target")
            image_entity_id = root_entity_id

            if isinstance(image_target, str) and image_target.strip():
                image_entity_id = self.add_entity(
                    "image",
                    image_target,
                    source_module=module_name,
                    confidence=0.95,
                    attributes={"image_source": data.get("image_source")},
                )
                if root_entity_id and image_entity_id != root_entity_id:
                    self.add_relation(
                        "investigated_as",
                        root_entity_id,
                        image_entity_id,
                        source_module=module_name,
                        confidence=0.95,
                        evidence_id=evidence_id,
                    )

            face_map: Dict[str, str] = {}
            for idx, face in enumerate((data.get("faces") or [])[:64]):
                if not isinstance(face, dict):
                    continue
                face_ref = str(face.get("face_id") or f"face_{idx + 1}")
                face_entity_id = self.add_entity(
                    "face",
                    f"{image_target or root_entity_id or 'image'}#{face_ref}",
                    display=face_ref,
                    source_module=module_name,
                    confidence=float(face.get("confidence") or 0.6),
                    attributes={
                        "bbox": face.get("bbox"),
                        "crop_path": face.get("crop_path"),
                        "crop_status": face.get("crop_status"),
                    },
                )
                face_map[face_ref] = face_entity_id
                if image_entity_id:
                    self.add_relation(
                        "contains_face",
                        image_entity_id,
                        face_entity_id,
                        source_module=module_name,
                        confidence=0.8,
                        evidence_id=evidence_id,
                    )

            for hit in (data.get("reverse_image_results") or [])[:300]:
                if not isinstance(hit, dict):
                    continue
                hit_url = hit.get("url")
                if not isinstance(hit_url, str):
                    continue

                url_entity_id = self.add_entity(
                    "url",
                    hit_url,
                    source_module=module_name,
                    confidence=0.82,
                    attributes={
                        "provider": hit.get("provider"),
                        "match_type": hit.get("match_type"),
                        "title": hit.get("title"),
                    },
                )
                source_face_id = face_map.get(str(hit.get("face_id") or ""))
                source_entity_id = source_face_id or image_entity_id or root_entity_id
                if source_entity_id:
                    self.add_relation(
                        "reverse_image_hit",
                        source_entity_id,
                        url_entity_id,
                        source_module=module_name,
                        confidence=0.8,
                        evidence_id=evidence_id,
                    )
                self._link_url_domain(hit_url, source_module=module_name, evidence_id=evidence_id)

            for item in (data.get("entities") or [])[:200]:
                if not isinstance(item, dict):
                    continue
                entity_type = str(item.get("type") or "").strip()
                entity_value = item.get("value")
                if not entity_type or not isinstance(entity_value, str) or not entity_value.strip():
                    continue

                if entity_type not in {
                    "person_name",
                    "username",
                    "email",
                    "domain",
                    "url",
                    "phone",
                    "ip",
                }:
                    continue

                ent_id = self.add_entity(
                    entity_type,
                    entity_value,
                    source_module=module_name,
                    confidence=0.72,
                    attributes={k: v for k, v in item.items() if k not in {"type", "value"}},
                )

                source_url = item.get("source_url")
                if isinstance(source_url, str) and source_url.strip():
                    source_url_id = self.add_entity(
                        "url",
                        source_url,
                        source_module=module_name,
                        confidence=0.7,
                    )
                    self.add_relation(
                        "mentions_entity",
                        source_url_id,
                        ent_id,
                        source_module=module_name,
                        confidence=0.7,
                        evidence_id=evidence_id,
                    )
                    self._link_url_domain(source_url, source_module=module_name, evidence_id=evidence_id)

                pivot_from = image_entity_id or root_entity_id
                if pivot_from:
                    self.add_relation(
                        "possible_identity",
                        pivot_from,
                        ent_id,
                        source_module=module_name,
                        confidence=0.6,
                        evidence_id=evidence_id,
                    )
            return
        if module_name == "Subdomain_Scanner":
            root_domain = data.get("target_domain")
            root_domain_id: Optional[str] = None
            if isinstance(root_domain, str) and root_domain.strip():
                root_domain_id = self.add_entity(
                    "domain", root_domain, source_module=module_name, confidence=0.95
                )
                self.add_relation(
                    "investigated_as",
                    root_entity_id,
                    root_domain_id,
                    source_module=module_name,
                    confidence=0.95,
                    evidence_id=evidence_id,
                )

            for sub in (data.get("subdomains") or [])[:200]:
                if not isinstance(sub, str):
                    continue
                sub_id = self.add_entity("domain", sub, source_module=module_name, confidence=0.8)
                if root_domain_id:
                    self.add_relation(
                        "subdomain_of",
                        sub_id,
                        root_domain_id,
                        source_module=module_name,
                        confidence=0.8,
                        evidence_id=evidence_id,
                    )

    def _extract_generic_indicators(
        self,
        module_name: str,
        data: Dict[str, Any],
        *,
        root_entity_id: Optional[str],
        evidence_id: str,
    ) -> None:
        text_values = list(self._flatten_text_values(data))
        if not text_values:
            text_values = [str(data)]

        seen_strings = set()
        for text in text_values:
            if not text or text in seen_strings:
                continue
            seen_strings.add(text)

            for email in EMAIL_RE.findall(text):
                email_id = self.add_entity(
                    "email", email, source_module=module_name, confidence=0.7
                )
                if root_entity_id:
                    self.add_relation(
                        "mentioned_in_result",
                        root_entity_id,
                        email_id,
                        source_module=module_name,
                        confidence=0.55,
                        evidence_id=evidence_id,
                    )

            for candidate_ip in IPV4_RE.findall(text):
                try:
                    ipaddress.ip_address(candidate_ip)
                except ValueError:
                    continue
                ip_id = self.add_entity(
                    "ip", candidate_ip, source_module=module_name, confidence=0.7
                )
                if root_entity_id:
                    self.add_relation(
                        "mentioned_in_result",
                        root_entity_id,
                        ip_id,
                        source_module=module_name,
                        confidence=0.55,
                        evidence_id=evidence_id,
                    )

            for url in URL_RE.findall(text):
                url_id = self.add_entity("url", url, source_module=module_name, confidence=0.65)
                self.add_evidence(module_name, kind="url", value=url, url=url)
                if root_entity_id:
                    self.add_relation(
                        "mentioned_in_result",
                        root_entity_id,
                        url_id,
                        source_module=module_name,
                        confidence=0.5,
                        evidence_id=evidence_id,
                    )
                self._link_url_domain(url, source_module=module_name, evidence_id=evidence_id)

            for domain in DOMAIN_RE.findall(text):
                if "@" in domain:
                    continue
                domain_id = self.add_entity(
                    "domain", domain, source_module=module_name, confidence=0.6
                )
                if root_entity_id:
                    self.add_relation(
                        "mentioned_in_result",
                        root_entity_id,
                        domain_id,
                        source_module=module_name,
                        confidence=0.45,
                        evidence_id=evidence_id,
                    )

    def _link_url_domain(self, url: str, *, source_module: str, evidence_id: str) -> None:
        try:
            parsed = urlparse(url)
        except Exception:
            return
        host = (parsed.hostname or "").strip()
        if not host:
            return
        try:
            ipaddress.ip_address(host)
            host_type = "ip"
        except ValueError:
            host_type = "domain"

        url_id = self.add_entity("url", url, source_module=source_module, confidence=0.8)
        host_id = self.add_entity(host_type, host, source_module=source_module, confidence=0.8)
        self.add_relation(
            "hosted_on",
            url_id,
            host_id,
            source_module=source_module,
            confidence=0.8,
            evidence_id=evidence_id,
        )

    def _flatten_text_values(self, value: Any, *, _seen: Optional[Set[int]] = None) -> Iterable[str]:
        if _seen is None:
            _seen = set()
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, (int, float, bool)):
            return [str(value)]

        obj_id = id(value)
        if obj_id in _seen:
            return []
        _seen.add(obj_id)

        values: List[str] = []
        if isinstance(value, list):
            for item in value:
                values.extend(self._flatten_text_values(item, _seen=_seen))
            return values

        if isinstance(value, dict):
            for item in value.values():
                values.extend(self._flatten_text_values(item, _seen=_seen))
            return values

        return [str(value)]

    def _module_summary(self, data: Dict[str, Any]) -> str:
        if not data:
            return "empty"
        keys = list(data.keys())[:8]
        return f"keys={keys}"

    def _canonicalize(self, entity_type: str, value: str) -> str:
        value = value.strip()
        if entity_type in {"email", "domain", "url", "username", "search_url", "image"}:
            return value.lower()
        if entity_type in {"username_candidate", "email_local_part_candidate"}:
            return value.lower()
        return value
