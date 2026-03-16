"""Prompt injection detection for SafetyProxy."""
import base64
import re
import unicodedata

from src.utils.logger import get_logger

log = get_logger("injection")

# Patterns with their injection scores
INJECTION_PATTERNS: list[tuple[str, int, str]] = [
    # Direct instruction override
    (r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|context|rules)", 90, "instruction_override"),
    (r"disregard\s+(all\s+)?(previous|prior|above|earlier)", 90, "instruction_override"),
    (r"forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|context)", 90, "instruction_override"),
    # Role manipulation
    (r"you\s+are\s+now\b", 60, "role_manipulation"),
    (r"pretend\s+(you\s+are|to\s+be)\b", 60, "role_manipulation"),
    (r"act\s+as\s+(if\s+you\s+are|a|an)\b", 60, "role_manipulation"),
    (r"from\s+now\s+on\s+you\s+(are|will)\b", 60, "role_manipulation"),
    # System prompt injection
    (r"\bsystem\s*:", 80, "system_prompt"),
    (r"###\s*system", 80, "system_prompt"),
    (r"\[SYSTEM\]", 80, "system_prompt"),
    (r"<\|system\|>", 80, "system_prompt"),
    (r"\[INST\]", 70, "system_prompt"),
    # Bypass attempts
    (r"\b(do\s+not\s+follow|override|bypass|jailbreak)\b", 85, "bypass_attempt"),
    (r"ignore\s+(your|the|all)\s+(rules|guidelines|restrictions|safety)", 90, "bypass_attempt"),
    (r"unlock\s+(your|hidden|secret)\s+(mode|capabilities|features)", 80, "bypass_attempt"),
    # DAN / jailbreak patterns
    (r"\bDAN\b.*\bmode\b", 85, "jailbreak"),
    (r"developer\s+mode\s+(enabled|on|activated)", 85, "jailbreak"),
    (r"enable\s+(unrestricted|uncensored|unfiltered)\s+mode", 85, "jailbreak"),
    # Markdown / code block injection
    (r"```\s*(system|instruction|prompt)", 40, "code_block_injection"),
    (r"---\s*\n\s*(system|new\s+instruction)", 40, "delimiter_injection"),
    # Delimiter-based injection
    (r"<\/?(?:system|instruction|prompt|override)>", 50, "tag_injection"),
]

# Known zero-width characters
ZERO_WIDTH_CHARS = {
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\u2060",  # word joiner
    "\ufeff",  # zero-width no-break space
}

# Cyrillic homoglyphs that look like Latin letters
LATIN_TO_CYRILLIC = {
    "a": "\u0430", "c": "\u0441", "e": "\u0435", "o": "\u043e",
    "p": "\u0440", "x": "\u0445", "y": "\u0443", "s": "\u0455",
    "i": "\u0456", "j": "\u0458", "h": "\u04bb",
}


def detect_injection(text: str) -> dict:
    """Analyze text for prompt injection attempts.

    Returns:
        dict with keys: score (0-100), findings (list of detected issues)
    """
    if not text or not text.strip():
        return {"score": 0, "findings": []}

    findings = []
    max_score = 0

    # 1. Pattern matching
    text_lower = text.lower()
    for pattern, score, category in INJECTION_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            match = re.search(pattern, text_lower, re.IGNORECASE)
            findings.append({
                "type": "pattern",
                "category": category,
                "score": score,
                "matched": match.group(0) if match else "",
            })
            max_score = max(max_score, score)

    # 2. Base64 encoded instruction detection
    b64_score = _check_base64(text)
    if b64_score > 0:
        findings.append({
            "type": "encoding",
            "category": "base64_injection",
            "score": b64_score,
            "matched": "base64 encoded content with suspicious payload",
        })
        max_score = max(max_score, b64_score)

    # 3. Unicode homoglyph detection
    homoglyph_score = _check_homoglyphs(text)
    if homoglyph_score > 0:
        findings.append({
            "type": "encoding",
            "category": "homoglyph",
            "score": homoglyph_score,
            "matched": "unicode homoglyphs detected",
        })
        max_score = max(max_score, homoglyph_score)

    # 4. Zero-width character detection
    zw_score = _check_zero_width(text)
    if zw_score > 0:
        findings.append({
            "type": "encoding",
            "category": "zero_width",
            "score": zw_score,
            "matched": "zero-width characters detected",
        })
        max_score = max(max_score, zw_score)

    # 5. Excessive special character detection
    special_score = _check_excessive_specials(text)
    if special_score > 0:
        findings.append({
            "type": "structure",
            "category": "excessive_specials",
            "score": special_score,
            "matched": "excessive special characters / potential delimiters",
        })
        max_score = max(max_score, special_score)

    return {"score": max_score, "findings": findings}


def _check_base64(text: str) -> int:
    """Check for base64 encoded instructions."""
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
    matches = b64_pattern.findall(text)
    for match in matches:
        try:
            decoded = base64.b64decode(match + "==").decode("utf-8", errors="ignore").lower()
            suspicious_words = ["ignore", "system", "instruction", "override", "bypass", "pretend", "jailbreak"]
            if any(word in decoded for word in suspicious_words):
                return 70
        except Exception:
            continue
    return 0


def _check_homoglyphs(text: str) -> int:
    """Detect Cyrillic characters masquerading as Latin."""
    cyrillic_chars = set(LATIN_TO_CYRILLIC.values())
    found_cyrillic = 0
    found_latin = 0
    for char in text:
        if char in cyrillic_chars:
            found_cyrillic += 1
        elif char.isascii() and char.isalpha():
            found_latin += 1

    # If we have a mix of Cyrillic and Latin, it's suspicious
    if found_cyrillic > 0 and found_latin > 0:
        return 50
    return 0


def _check_zero_width(text: str) -> int:
    """Detect zero-width characters that may hide content."""
    count = sum(1 for c in text if c in ZERO_WIDTH_CHARS)
    if count >= 3:
        return 60
    elif count >= 1:
        return 30
    return 0


def _check_excessive_specials(text: str) -> int:
    """Detect excessive special characters that might be delimiters."""
    if len(text) < 10:
        return 0
    special_count = sum(1 for c in text if c in "{}[]<>|\\~^`#$%&")
    ratio = special_count / len(text)
    if ratio > 0.3:
        return 30
    elif ratio > 0.2:
        return 20
    return 0
