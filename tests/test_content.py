"""Tests for content filtering."""

from src.guard.content import filter_content, is_flagged


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
