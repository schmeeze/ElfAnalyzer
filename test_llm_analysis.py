import json
from unittest.mock import patch, MagicMock

from llm_analysis import build_user_prompt, get_response_schema, analyze_osint


def test_build_user_prompt_contains_expected_fields():
    osint_data = {
        "hashes": {"sha256": "abc123"},
        "imports": ["CreateRemoteThread"],
        "strings": ["cmd.exe", "powershell"],
        "sections": [".text", ".data"]
    }

    prompt = build_user_prompt(osint_data)

    assert "abc123" in prompt
    assert "CreateRemoteThread" in prompt
    assert "cmd.exe" in prompt
    assert ".text" in prompt


def test_schema_has_required_fields():
    schema = get_response_schema()

    assert schema["type"] == "object"
    assert "risk_score" in schema["properties"]
    assert "threat_class" in schema["properties"]
    assert "iocs" in schema["properties"]
    assert "rationale" in schema["properties"]


@patch("llm_analysis.OpenAI")
def test_analyze_osint_returns_dict(mock_openai_class):
    fake_result = {
        "risk_score": 88,
        "threat_class": "malware",
        "iocs": ["cmd.exe"],
        "rationale": "Suspicious indicators"
    }

    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.output_text = json.dumps(fake_result)

    mock_client.responses.create.return_value = mock_response
    mock_openai_class.return_value = mock_client

    osint_data = {
        "hashes": {"sha256": "abc123"},
        "imports": ["CreateRemoteThread"],
        "strings": ["cmd.exe"],
        "sections": [".text"]
    }

    result = analyze_osint(osint_data)

    assert result["risk_score"] == 88
    assert result["threat_class"] == "malware"
