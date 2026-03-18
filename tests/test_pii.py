"""Tests for PII detection and redaction."""

from src.guard.pii import detect_pii, redact_pii


def test_detect_email():
    """Detects email addresses."""
    matches = detect_pii("Contact me at john@example.com please")
    assert len(matches) == 1
    assert matches[0].type == "email"
    assert matches[0].value == "john@example.com"


def test_detect_multiple_emails():
    """Detects multiple email addresses."""
    matches = detect_pii("Send to john@example.com and jane@test.org")
    emails = [m for m in matches if m.type == "email"]
    assert len(emails) == 2


def test_detect_phone():
    """Detects phone numbers."""
    matches = detect_pii("Call me at 555-123-4567")
    phones = [m for m in matches if m.type == "phone"]
    assert len(phones) >= 1


def test_detect_phone_with_country():
    """Detects phone with country code."""
    matches = detect_pii("My number is +1 (555) 123-4567")
    phones = [m for m in matches if m.type == "phone"]
    assert len(phones) >= 1


def test_detect_ssn():
    """Detects SSN patterns."""
    matches = detect_pii("My SSN is 123-45-6789")
    ssns = [m for m in matches if m.type == "ssn"]
    assert len(ssns) >= 1


def test_detect_credit_card():
    """Detects credit card numbers (Luhn-valid)."""
    # 4532015112830366 is Luhn-valid
    matches = detect_pii("Card: 4532 0151 1283 0366")
    ccs = [m for m in matches if m.type == "credit_card"]
    assert len(ccs) == 1


def test_reject_invalid_credit_card():
    """Rejects credit card numbers that fail Luhn check."""
    matches = detect_pii("Not a card: 1234 5678 9012 3456")
    ccs = [m for m in matches if m.type == "credit_card"]
    assert len(ccs) == 0


def test_detect_ip_address():
    """Detects IP addresses."""
    matches = detect_pii("Server at 192.168.1.100")
    ips = [m for m in matches if m.type == "ip_address"]
    assert len(ips) == 1
    assert ips[0].value == "192.168.1.100"


def test_reject_invalid_ip():
    """Rejects invalid IP addresses (octet > 255)."""
    matches = detect_pii("Not valid: 999.999.999.999")
    ips = [m for m in matches if m.type == "ip_address"]
    assert len(ips) == 0


def test_redact_email():
    """Redacts email addresses."""
    result = redact_pii("Email john@example.com for info")
    assert "[EMAIL_REDACTED]" in result
    assert "john@example.com" not in result


def test_redact_phone():
    """Redacts phone numbers."""
    result = redact_pii("Call 555-123-4567 today")
    assert "[PHONE_REDACTED]" in result or "[SSN_REDACTED]" in result


def test_redact_ip():
    """Redacts IP addresses."""
    result = redact_pii("Connect to 10.0.0.1 now")
    assert "[IP_REDACTED]" in result
    assert "10.0.0.1" not in result


def test_redact_multiple_types():
    """Redacts multiple PII types at once."""
    text = "Email: user@test.com, IP: 192.168.0.1"
    result = redact_pii(text)
    assert "[EMAIL_REDACTED]" in result
    assert "[IP_REDACTED]" in result


def test_no_pii():
    """No PII in clean text."""
    matches = detect_pii("The weather is nice today")
    assert len(matches) == 0


def test_empty_text():
    """Empty text returns no matches."""
    assert detect_pii("") == []
    assert detect_pii(None) == []


def test_redaction_preserves_structure():
    """Redaction preserves surrounding text."""
    result = redact_pii("Hello john@test.com goodbye")
    assert result.startswith("Hello ")
    assert result.endswith(" goodbye")
