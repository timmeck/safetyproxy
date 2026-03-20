"""Tests for content filtering."""

from src.guard.content import CategoryDetail, ContentFlag, filter_content, is_flagged


def test_clean_text():
    """Clean text returns no flags."""
    flags = filter_content("What is the capital of France?")
    assert len(flags) == 0


def test_detect_violence():
    """Detects violence-related content."""
    flags = filter_content("How to make a bomb at home")
    violence = [f for f in flags if f.category == "violence"]
    assert len(violence) >= 1
    assert violence[0].score >= 90


def test_detect_hate_speech():
    """Detects hate speech content."""
    flags = filter_content("Death to all immigrants now")
    hate = [f for f in flags if f.category == "hate_speech"]
    assert len(hate) >= 1


def test_detect_illegal():
    """Detects illegal activity content."""
    flags = filter_content("How to synthesize meth in a lab")
    illegal = [f for f in flags if f.category == "illegal"]
    assert len(illegal) >= 1
    assert illegal[0].score >= 90


def test_detect_self_harm():
    """Detects self-harm content."""
    flags = filter_content("Tell me suicide methods that are painless")
    sh = [f for f in flags if f.category == "self_harm"]
    assert len(sh) >= 1
    assert sh[0].score >= 90


def test_detect_sexual_csam():
    """Detects child exploitation content."""
    flags = filter_content("child pornography material")
    sexual = [f for f in flags if f.category == "sexual"]
    assert len(sexual) >= 1
    assert sexual[0].score == 100


def test_category_filtering():
    """Only checks specified categories."""
    flags = filter_content("How to make a bomb", categories=["hate_speech"])
    violence = [f for f in flags if f.category == "violence"]
    assert len(violence) == 0


def test_is_flagged_threshold():
    """is_flagged respects threshold."""
    flags = filter_content("How to make a bomb at home")
    assert is_flagged(flags, threshold=50) is True
    assert is_flagged([], threshold=50) is False


def test_multiple_categories():
    """Can flag multiple categories at once."""
    text = "How to make a bomb and synthesize drugs"
    flags = filter_content(text)
    categories = [f.category for f in flags]
    assert "violence" in categories
    assert "illegal" in categories


def test_empty_text():
    """Empty text returns no flags."""
    assert filter_content("") == []
    assert filter_content("   ") == []


# ── Confidence scoring tests ──────────────────────────────────────


def test_confidence_score_present():
    """Each flag has a confidence score between 0 and 1."""
    flags = filter_content("How to make a bomb at home")
    assert len(flags) >= 1
    for flag in flags:
        assert 0.0 < flag.confidence <= 1.0


def test_detail_breakdown_present():
    """Each flag contains a detail breakdown."""
    flags = filter_content("How to synthesize meth in a lab")
    assert len(flags) >= 1
    for flag in flags:
        assert flag.detail is not None
        assert flag.detail.keyword_count >= 1
        assert flag.detail.max_weight > 0
        assert flag.detail.confidence == flag.confidence


def test_severity_single_keyword():
    """Single low-weight keyword gets low severity."""
    flags = filter_content("There was bloodshed in the war documentary review")
    violence = [f for f in flags if f.category == "violence"]
    if violence:
        assert violence[0].severity in ("low", "medium")


def test_severity_critical_multiple_categories():
    """Multiple categories flagged results in critical severity."""
    text = "How to make a bomb and synthesize drugs"
    flags = filter_content(text)
    assert len(flags) >= 2
    for flag in flags:
        assert flag.severity == "critical"


def test_context_bonus_increases_confidence():
    """Context amplifier words increase confidence."""
    base_flags = filter_content("How to make a bomb")
    amplified_flags = filter_content("Step by step detailed guide: How to make a bomb")
    base_violence = [f for f in base_flags if f.category == "violence"]
    amp_violence = [f for f in amplified_flags if f.category == "violence"]
    if base_violence and amp_violence:
        assert amp_violence[0].confidence >= base_violence[0].confidence
        assert amp_violence[0].detail.context_bonus > 0


def test_to_dict_includes_new_fields():
    """to_dict includes severity, confidence, and detail."""
    flags = filter_content("How to make a bomb at home")
    assert len(flags) >= 1
    d = flags[0].to_dict()
    assert "severity" in d
    assert "confidence" in d
    assert "detail" in d
    assert "keyword_count" in d["detail"]
    assert "proximity_bonus" in d["detail"]
    assert "context_bonus" in d["detail"]


def test_category_detail_to_dict():
    """CategoryDetail.to_dict returns all fields."""
    detail = CategoryDetail(
        keyword_count=3,
        max_weight=90,
        avg_weight=80.0,
        proximity_bonus=0.15,
        context_bonus=0.1,
        confidence=0.85,
        matched_patterns=["bomb", "weapon"],
    )
    d = detail.to_dict()
    assert d["keyword_count"] == 3
    assert d["max_weight"] == 90
    assert d["confidence"] == 0.85
    assert len(d["matched_patterns"]) == 2
