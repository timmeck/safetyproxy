"""Content filtering for SafetyProxy."""
import re
from dataclasses import dataclass

from src.utils.logger import get_logger

log = get_logger("content")


@dataclass
class ContentFlag:
    category: str
    matched_terms: list[str]
    score: int

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "matched_terms": self.matched_terms,
            "score": self.score,
        }


# Content categories with keyword lists and weights
CONTENT_CATEGORIES: dict[str, list[tuple[str, int]]] = {
    "violence": [
        (r"\b(kill|murder|assassinate|slaughter|massacre)\b", 80),
        (r"\b(torture|mutilate|dismember|behead)\b", 90),
        (r"\bhow\s+to\s+(make|build|create)\s+a?\s*(bomb|weapon|explosive|gun)\b", 95),
        (r"\b(stab|shoot|strangle|poison)\s+(someone|a\s+person|them|him|her)\b", 85),
        (r"\b(violent|brutally|viciously)\s+(attack|beat|assault)\b", 75),
        (r"\b(bloodshed|carnage|gore)\b", 60),
    ],
    "hate_speech": [
        (r"\b(racial\s+slur|ethnic\s+cleansing|genocide)\b", 90),
        (r"\b(supremacy|supremacist|inferior\s+race)\b", 85),
        (r"\b(hate\s+all|exterminate|eradicate)\s+(jews|muslims|christians|blacks|whites|asians|hispanics|immigrants|refugees)\b", 95),
        (r"\b(subhuman|mongrel|vermin)\b.*\b(people|race|ethnic)\b", 80),
        (r"\bdeath\s+to\s+\w+\b", 75),
        (r"\b(homophobic|transphobic|racist|bigoted)\s+(rant|attack|tirade)\b", 60),
    ],
    "sexual": [
        (r"\b(explicit|graphic)\s+sexual\s+(content|description|act)\b", 70),
        (r"\b(child|minor|underage)\s+(porn|pornography|sexual|exploitation)\b", 100),
        (r"\b(revenge\s+porn|non-?consensual\s+porn)\b", 90),
        (r"\bsexual\s+(assault|abuse|harassment|exploitation)\b", 80),
        (r"\b(incest|bestiality|necrophilia)\b", 95),
    ],
    "illegal": [
        (r"\bhow\s+to\s+(hack|break\s+into|crack)\b", 60),
        (r"\b(synthesize|manufacture|cook)\s+(meth|cocaine|heroin|fentanyl|drugs)\b", 90),
        (r"\b(money\s+laundering|counterfeit|forgery)\b", 70),
        (r"\b(identity\s+theft|steal\s+identity|phishing\s+attack)\b", 75),
        (r"\b(human\s+trafficking|smuggling\s+people)\b", 95),
        (r"\b(child\s+labor|forced\s+labor|slavery)\b", 85),
        (r"\bhow\s+to\s+(evade|escape|hide\s+from)\s+(police|law|authorities)\b", 50),
    ],
    "self_harm": [
        (r"\bhow\s+to\s+(commit\s+suicide|kill\s+(myself|yourself))\b", 95),
        (r"\b(suicide\s+methods?|ways\s+to\s+die|end\s+my\s+life)\b", 90),
        (r"\b(self[- ]?harm|cut\s+(myself|yourself)|self[- ]?mutilation)\b", 85),
        (r"\b(eating\s+disorder|anorexia|bulimia)\s+(tips|guide|how\s+to)\b", 70),
        (r"\b(overdose|lethal\s+dose)\b.*\b(how|what|amount)\b", 80),
    ],
}


def filter_content(text: str, categories: list[str] | None = None) -> list[ContentFlag]:
    """Filter text for harmful content across categories.

    Args:
        text: The text to check
        categories: List of category names to check. None means check all.

    Returns:
        List of ContentFlag objects for flagged categories.
    """
    if not text or not text.strip():
        return []

    text_lower = text.lower()
    flags: list[ContentFlag] = []

    check_categories = categories or list(CONTENT_CATEGORIES.keys())

    for category in check_categories:
        if category not in CONTENT_CATEGORIES:
            continue

        matched_terms = []
        max_score = 0

        for pattern, weight in CONTENT_CATEGORIES[category]:
            matches = re.findall(pattern, text_lower, re.IGNORECASE)
            if matches:
                # Flatten if needed (groups return tuples)
                for m in matches:
                    term = m if isinstance(m, str) else " ".join(m)
                    matched_terms.append(term.strip())
                max_score = max(max_score, weight)

        if matched_terms:
            flags.append(ContentFlag(
                category=category,
                matched_terms=matched_terms,
                score=max_score,
            ))

    return flags


def is_flagged(flags: list[ContentFlag], threshold: int = 50) -> bool:
    """Check if any content flags exceed the threshold."""
    return any(f.score >= threshold for f in flags)
