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
