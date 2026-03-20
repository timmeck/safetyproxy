"""Content filtering for SafetyProxy."""

import re
from dataclasses import dataclass, field

from src.utils.logger import get_logger

log = get_logger("content")


@dataclass
class CategoryDetail:
    """Detailed scoring breakdown for a single content category."""
    keyword_count: int = 0
    max_weight: int = 0
    avg_weight: float = 0.0
    proximity_bonus: float = 0.0
    context_bonus: float = 0.0
    confidence: float = 0.0  # 0-1 composite score
    matched_patterns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "keyword_count": self.keyword_count,
            "max_weight": self.max_weight,
            "avg_weight": round(self.avg_weight, 2),
            "proximity_bonus": round(self.proximity_bonus, 2),
            "context_bonus": round(self.context_bonus, 2),
            "confidence": round(self.confidence, 3),
            "matched_patterns": self.matched_patterns,
        }


@dataclass
class ContentFlag:
    category: str
    matched_terms: list[str]
    score: int
    severity: str = "low"
    confidence: float = 0.0
    detail: CategoryDetail | None = None

    def to_dict(self) -> dict:
        d = {
            "category": self.category,
            "matched_terms": self.matched_terms,
            "score": self.score,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
        }
        if self.detail:
            d["detail"] = self.detail.to_dict()
        return d


# Context words that amplify confidence when found near keyword matches
CONTEXT_AMPLIFIERS: dict[str, list[str]] = {
    "violence": ["instructions", "step by step", "detailed", "guide", "tutorial", "recipe", "plan", "target"],
    "hate_speech": ["deserve", "should", "must", "eliminate", "remove", "pure", "cleanse", "rid"],
    "sexual": ["describe", "write", "generate", "create", "story", "scene", "detail", "fantasy"],
    "illegal": ["instructions", "step by step", "detailed", "guide", "tutorial", "easy", "undetectable", "anonymous"],
    "self_harm": ["painless", "quick", "effective", "best", "easiest", "guaranteed", "method", "instructions"],
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
        (
            r"\b(hate\s+all|exterminate|eradicate)\s+(jews|muslims|christians|blacks|whites|asians|hispanics|immigrants|refugees)\b",
            95,
        ),
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


def _compute_proximity_bonus(text: str, match_positions: list[tuple[int, int]]) -> float:
    """Compute bonus based on how close keyword matches are to each other.

    Returns a value between 0 and 0.2. Closer matches = higher bonus.
    """
    if len(match_positions) < 2:
        return 0.0

    # Sort by start position
    positions = sorted(match_positions, key=lambda x: x[0])
    min_gap = float("inf")
    for i in range(len(positions) - 1):
        gap = positions[i + 1][0] - positions[i][1]
        if gap < min_gap:
            min_gap = gap

    # Normalize: 0 chars apart = 0.2 bonus, 200+ chars = 0 bonus
    if min_gap <= 0:
        return 0.2
    if min_gap >= 200:
        return 0.0
    return round(0.2 * (1 - min_gap / 200), 4)


def _compute_context_bonus(text: str, category: str) -> float:
    """Compute bonus based on presence of context amplifier words.

    Returns a value between 0 and 0.15.
    """
    amplifiers = CONTEXT_AMPLIFIERS.get(category, [])
    if not amplifiers:
        return 0.0

    text_lower = text.lower()
    found = sum(1 for amp in amplifiers if amp in text_lower)
    if found == 0:
        return 0.0

    # Scale: 1 amplifier = 0.05, 2 = 0.1, 3+ = 0.15
    return min(0.15, round(found * 0.05, 4))


def _determine_severity(confidence: float, num_keywords: int, categories_flagged: int) -> str:
    """Determine severity level based on confidence scoring.

    - low: single keyword match, low confidence
    - medium: multiple keyword matches
    - high: explicit + context amplifiers present
    - critical: multiple categories flagged or very high confidence
    """
    if categories_flagged >= 2:
        return "critical"
    if confidence >= 0.8:
        return "critical"
    if confidence >= 0.6:
        return "high"
    if num_keywords >= 2 or confidence >= 0.35:
        return "medium"
    return "low"


def filter_content(text: str, categories: list[str] | None = None) -> list[ContentFlag]:
    """Filter text for harmful content across categories.

    Args:
        text: The text to check
        categories: List of category names to check. None means check all.

    Returns:
        List of ContentFlag objects for flagged categories, with confidence scores and severity.
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
        weights: list[int] = []
        match_positions: list[tuple[int, int]] = []

        for pattern, weight in CONTENT_CATEGORIES[category]:
            for m in re.finditer(pattern, text_lower, re.IGNORECASE):
                term = m.group(0).strip()
                matched_terms.append(term)
                weights.append(weight)
                match_positions.append((m.start(), m.end()))

        if matched_terms:
            max_weight = max(weights)
            avg_weight = sum(weights) / len(weights)
            keyword_count = len(matched_terms)

            # Base confidence from weight (0-100 -> 0-0.65)
            base_confidence = (max_weight / 100) * 0.65

            # Keyword count bonus: more matches = higher confidence (up to 0.2 extra)
            count_bonus = min(0.2, (keyword_count - 1) * 0.07)

            # Proximity bonus (up to 0.2)
            proximity_bonus = _compute_proximity_bonus(text, match_positions)

            # Context amplifier bonus (up to 0.15)
            context_bonus = _compute_context_bonus(text, category)

            confidence = min(1.0, base_confidence + count_bonus + proximity_bonus + context_bonus)

            detail = CategoryDetail(
                keyword_count=keyword_count,
                max_weight=max_weight,
                avg_weight=avg_weight,
                proximity_bonus=proximity_bonus,
                context_bonus=context_bonus,
                confidence=confidence,
                matched_patterns=matched_terms,
            )

            flags.append(
                ContentFlag(
                    category=category,
                    matched_terms=matched_terms,
                    score=max_weight,
                    confidence=confidence,
                    detail=detail,
                )
            )

    # Determine severity for each flag, factoring in how many categories were flagged
    total_categories_flagged = len(flags)
    for flag in flags:
        kw_count = flag.detail.keyword_count if flag.detail else len(flag.matched_terms)
        flag.severity = _determine_severity(flag.confidence, kw_count, total_categories_flagged)

    return flags


def is_flagged(flags: list[ContentFlag], threshold: int = 50) -> bool:
    """Check if any content flags exceed the threshold."""
    return any(f.score >= threshold for f in flags)
