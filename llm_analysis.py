
import os
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def analyze_malware(data):
    prompt = f"""
You are a cybersecurity analyst.

Analyze the following data and return:
- risk_score (0-100)
- threat_type
- iocs (list)

Data:
{data}

Return ONLY JSON.
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a cybersecurity analyst."},
            {"role": "user", "content": prompt}
        ]
    )

    return response.choices[0].message.content


# test run
if __name__ == "__main__":
    sample_data = {
        "strings": ["cmd.exe", "powershell", "http://malicious.com"],
        "imports": ["kernel32.dll", "ws2_32.dll"]
    }

    print(analyze_malware(sample_data))
# =======
import json
from typing import Any, Dict

from openai import OpenAI


SYSTEM_PROMPT = """
You are a malware triage assistant.

Your job:
1. Review OSINT-style binary analysis data.
2. Classify the sample.
3. Return ONLY valid JSON that matches the requested schema.

Rules:
- Be conservative. Do not call something malware unless indicators support it.
- Use the evidence provided only.
- risk_score must be an integer from 0 to 100.
- threat_class must be one of:
  ["malware", "suspicious", "benign", "unknown"]
- iocs must be a list of short strings.
- rationale must be brief and evidence-based.
"""


def build_user_prompt(osint_data: Dict[str, Any]) -> str:
    hashes = osint_data.get("hashes", {})
    imports_ = osint_data.get("imports", [])
    strings = osint_data.get("strings", [])
    sections = osint_data.get("sections", [])

    strings_preview = strings[:40]
    imports_preview = imports_[:50]
    sections_preview = sections[:20]

    prompt = f"""
Analyze this binary OSINT data.

Hashes:
{json.dumps(hashes, indent=2)}

Imports:
{json.dumps(imports_preview, indent=2)}

Printable Strings:
{json.dumps(strings_preview, indent=2)}

Sections:
{json.dumps(sections_preview, indent=2)}

Return a JSON object with:
- risk_score
- threat_class
- iocs
- rationale
"""
    return prompt.strip()


def get_response_schema() -> Dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "risk_score": {
                "type": "integer",
                "minimum": 0,
                "maximum": 100
            },
            "threat_class": {
                "type": "string",
                "enum": ["malware", "suspicious", "benign", "unknown"]
            },
            "iocs": {
                "type": "array",
                "items": {"type": "string"}
            },
            "rationale": {
                "type": "string"
            }
        },
        "required": ["risk_score", "threat_class", "iocs", "rationale"],
        "additionalProperties": False
    }


def analyze_osint(osint_data: Dict[str, Any], model: str = "gpt-4.1-mini") -> Dict[str, Any]:
    client = OpenAI()

    user_prompt = build_user_prompt(osint_data)
    schema = get_response_schema()

    response = client.responses.create(
        model=model,
        input=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        text={
            "format": {
                "type": "json_schema",
                "name": "malware_triage_result",
                "schema": schema,
                "strict": True,
            }
        }
    )

    return json.loads(response.output_text)


if __name__ == "__main__":
    sample_osint = {
        "hashes": {
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb924"
        },
        "imports": ["CreateRemoteThread", "VirtualAlloc", "LoadLibraryA"],
        "strings": ["http://bad-domain.example", "powershell -enc ...", "cmd.exe"],
        "sections": [".text", ".rdata", ".data"]
    }

    result = analyze_osint(sample_osint)
    print(json.dumps(result, indent=2))

