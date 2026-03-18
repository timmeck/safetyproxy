"""PII detection and redaction for SafetyProxy."""

import re
from dataclasses import dataclass

from src.utils.logger import get_logger

log = get_logger("pii")


@dataclass
class PIIMatch:
    type: str
    value: str
    start: int
    end: int
    redacted_text: str

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "value": self.value,
            "start": self.start,
            "end": self.end,
            "redacted_text": self.redacted_text,
        }


# PII patterns with their types and redaction labels
PII_PATTERNS: list[tuple[str, str, str]] = [
    # SSN must come before phone to avoid false matches
    (r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b", "ssn", "[SSN_REDACTED]"),
    # Credit card
    (r"\b(?:\d{4}[-\s]?){3}\d{4}\b", "credit_card", "[CC_REDACTED]"),
    # Email
    (r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", "email", "[EMAIL_REDACTED]"),
    # Phone
    (r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "phone", "[PHONE_REDACTED]"),
    # IP address
    (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "ip_address", "[IP_REDACTED]"),
]


def detect_pii(text: str) -> list[PIIMatch]:
    """Detect PII in the given text.

    Returns a list of PIIMatch objects with type, value, position, and redacted text.
    """
    if not text:
        return []

    matches: list[PIIMatch] = []
    seen_spans: set[tuple[int, int]] = set()

    for pattern, pii_type, redaction_label in PII_PATTERNS:
        for match in re.finditer(pattern, text):
            span = (match.start(), match.end())
            # Skip overlapping matches
            overlaps = False
            for existing_start, existing_end in seen_spans:
                if span[0] < existing_end and span[1] > existing_start:
                    overlaps = True
                    break
            if overlaps:
                continue

            value = match.group(0)

            # Validate IP addresses (each octet 0-255)
            if pii_type == "ip_address":
                octets = value.split(".")
                if not all(0 <= int(o) <= 255 for o in octets):
                    continue

            # Validate credit card with basic Luhn check
            if pii_type == "credit_card":
                digits = re.sub(r"[-\s]", "", value)
                if not _luhn_check(digits):
                    continue

            seen_spans.add(span)
            matches.append(
                PIIMatch(
                    type=pii_type,
                    value=value,
                    start=match.start(),
                    end=match.end(),
                    redacted_text=redaction_label,
                )
            )

    # Sort by position
    matches.sort(key=lambda m: m.start)
    return matches


def redact_pii(text: str, matches: list[PIIMatch] | None = None) -> str:
    """Redact all detected PII from text.

    If matches are not provided, detects them first.
    """
    if matches is None:
        matches = detect_pii(text)

    if not matches:
        return text

    # Process replacements from end to start to maintain positions
    result = text
    for match in sorted(matches, key=lambda m: m.start, reverse=True):
        result = result[: match.start] + match.redacted_text + result[match.end :]

    return result


def _luhn_check(number: str) -> bool:
    """Validate a number string using the Luhn algorithm."""
    if not number.isdigit() or len(number) < 13:
        return False
    digits = [int(d) for d in number]
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    total = sum(odd_digits)
    for d in even_digits:
        d *= 2
        if d > 9:
            d -= 9
        total += d
    return total % 10 == 0
