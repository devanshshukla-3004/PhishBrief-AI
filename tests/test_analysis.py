import pytest
from core import MAX_MESSAGE_CHARS, analyze_message, heuristic_preview, validate_result


def test_demo_preview_detects_urgency_and_link():
    result = heuristic_preview("URGENT: verify your account at https://example.com immediately")
    titles = {item["title"] for item in result["indicators"]}
    assert "Urgency or pressure" in titles
    assert "Link included" in titles
    assert result["analysis_mode"] == "Demo preview (not AI)"
    assert 0 <= result["risk_score"] <= 100


def test_demo_preview_does_not_claim_message_is_malicious():
    result = heuristic_preview("Hi, the meeting is at 3 PM.")
    assert "does not establish" in result["indicators"][0]["why_it_matters"]


def test_empty_message_rejected():
    with pytest.raises(ValueError):
        heuristic_preview("  ")


def test_oversized_message_rejected_before_network_call():
    with pytest.raises(ValueError, match="characters"):
        analyze_message("x" * (MAX_MESSAGE_CHARS + 1))


def test_invalid_model_schema_rejected():
    with pytest.raises(ValueError):
        validate_result({"risk_level": "Critical", "risk_score": 150})


def test_valid_result_is_sanitized_and_bounded():
    raw = {
        "risk_level": "Medium", "risk_score": 50, "summary": "Review carefully.",
        "indicators": [{"title": "Link", "evidence": "http://example.invalid", "why_it_matters": "Verify independently."}],
        "recommended_actions": ["Do not click."], "limitations": ["No live URL scan."],
    }
    result = validate_result(raw)
    assert result["risk_level"] == "Medium"
    assert result["indicators"][0]["title"] == "Link"
