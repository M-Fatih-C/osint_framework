import re
import unicodedata
from collections import OrderedDict
from typing import Dict, List


_WS_RE = re.compile(r"\s+")
_VALID_HANDLE_RE = re.compile(r"^[A-Za-z0-9._-]{2,64}$")
_TURKISH_ASCII_MAP = str.maketrans(
    {
        "ç": "c",
        "Ç": "C",
        "ğ": "g",
        "Ğ": "G",
        "ı": "i",
        "İ": "I",
        "ö": "o",
        "Ö": "O",
        "ş": "s",
        "Ş": "S",
        "ü": "u",
        "Ü": "U",
    }
)


def normalize_person_name(value: str) -> str:
    value = _WS_RE.sub(" ", (value or "").strip())
    return value


def split_name_parts(value: str) -> List[str]:
    normalized = normalize_person_name(value)
    if not normalized:
        return []

    parts: List[str] = []
    for raw in normalized.split(" "):
        token = raw.strip(" .-")
        if token:
            parts.append(token)
    return parts


def ascii_fold(value: str) -> str:
    mapped = (value or "").translate(_TURKISH_ASCII_MAP)
    normalized = unicodedata.normalize("NFKD", mapped)
    return "".join(ch for ch in normalized if not unicodedata.combining(ch))


def build_name_analysis(value: str) -> Dict[str, object]:
    normalized = normalize_person_name(value)
    parts = split_name_parts(normalized)
    lower = normalized.lower()
    ascii_name = ascii_fold(normalized)
    ascii_lower = ascii_name.lower()

    initials = "".join(p[0].upper() for p in parts if p)
    first = parts[0] if parts else ""
    last = parts[-1] if len(parts) >= 2 else (parts[0] if parts else "")
    middle = parts[1:-1] if len(parts) > 2 else []

    variants = _dedupe_preserve(
        [
            normalized,
            lower,
            ascii_name,
            ascii_lower,
            " ".join(parts),
            " ".join(reversed(parts)) if len(parts) > 1 else "",
            "".join(parts),
            "".join(parts).lower(),
            "".join(parts).upper(),
        ]
    )

    return {
        "normalized": normalized,
        "parts": parts,
        "part_count": len(parts),
        "first_name": first,
        "middle_names": middle,
        "last_name": last,
        "initials": initials,
        "ascii_transliteration": ascii_name,
        "variants": variants,
    }


def generate_username_candidates(value: str, limit: int = 80) -> List[str]:
    info = build_name_analysis(value)
    parts = [ascii_fold(p).lower() for p in info["parts"] if p]
    if not parts:
        return []

    first = parts[0]
    last = parts[-1] if len(parts) > 1 else ""
    middle = parts[1:-1]
    all_joined = "".join(parts)
    initials = "".join(p[0] for p in parts if p)
    first_initial = first[:1]
    last_initial = last[:1] if last else ""

    candidates = [
        first,
        last,
        all_joined,
        f"{first}{last}" if last else "",
        f"{first}.{last}" if last else "",
        f"{first}_{last}" if last else "",
        f"{first}-{last}" if last else "",
        f"{last}{first}" if last else "",
        f"{last}.{first}" if last else "",
        f"{first_initial}{last}" if first_initial and last else "",
        f"{first}{last_initial}" if first and last_initial else "",
        initials,
        f"{initials}{last}" if initials and last else "",
        f"{first}.{initials}" if first and initials else "",
    ]

    if middle:
        mid_initials = "".join(p[:1] for p in middle)
        candidates.extend(
            [
                f"{first}{mid_initials}{last}" if last else "",
                f"{first}.{mid_initials}.{last}" if last and mid_initials else "",
                f"{first}_{mid_initials}_{last}" if last and mid_initials else "",
                f"{first_initial}{mid_initials}{last}" if last and mid_initials else "",
            ]
        )

    # Add compact no-space variants from normalized/original transliterated forms.
    normalized_ascii = ascii_fold(info["normalized"]).lower()
    compact = normalized_ascii.replace(" ", "")
    dotted = normalized_ascii.replace(" ", ".")
    underscored = normalized_ascii.replace(" ", "_")
    hyphenated = normalized_ascii.replace(" ", "-")
    candidates.extend([compact, dotted, underscored, hyphenated])

    cleaned = []
    for candidate in _dedupe_preserve(candidates):
        if not candidate:
            continue
        c = candidate.strip(".-_")
        if not c:
            continue
        if _VALID_HANDLE_RE.match(c):
            cleaned.append(c)
        if len(cleaned) >= limit:
            break

    return cleaned


def generate_email_local_parts(value: str, limit: int = 50) -> List[str]:
    usernames = generate_username_candidates(value, limit=limit * 2)
    locals_out: List[str] = []
    for item in usernames:
        if "." in item or "_" in item or "-" in item:
            locals_out.append(item)
        locals_out.append(item.replace("_", ".").replace("-", "."))
        if len(locals_out) >= limit * 2:
            break

    # Email local part allows more chars, but we keep it conservative.
    return _dedupe_preserve([x for x in locals_out if 1 <= len(x) <= 64])[:limit]


def _dedupe_preserve(values: List[str]) -> List[str]:
    out = OrderedDict()
    for value in values:
        if not value:
            continue
        out[str(value)] = None
    return list(out.keys())
