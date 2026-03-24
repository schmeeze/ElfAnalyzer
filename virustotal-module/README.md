# VirusTotal Integration Module
**Mohith's Module — Class Collaboration Project**

This module handles all VirusTotal communication for the project. It accepts file uploads, submits them to VirusTotal, waits for the scan to complete, and returns structured results for the report module and other teammates to consume.

---

## What This Module Does

1. Receives a file via the `/scan` endpoint
2. Uploads it to VirusTotal's API
3. Polls every 15 seconds until the scan is complete
4. Returns a clean JSON response with detection results

---

## Setup

### 1. Install dependencies
```
pip install -r requirements.txt
```

### 2. Create your `.env` file
Create a file called `.env` in this folder with your VirusTotal API key:
```
VT_API_KEY=your_api_key_here
```
Get your free API key at [virustotal.com](https://virustotal.com) → sign in → profile icon → API Key.

> ⚠️ Never share your `.env` file or commit it to GitHub. It is already listed in `.gitignore`.

### 3. Run the server
```
python -m uvicorn virustotal:app --reload
```

The server starts at `http://localhost:8000`

---

## API Endpoint

### `POST /scan`

Uploads a file to VirusTotal and returns scan results.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `file` | File | Yes | The file to scan |
| `password` | String | No | Zip password if needed (use `infected` for Malware Bazaar samples) |

### Example Response
```json
{
  "filename": "malware.zip",
  "status": "completed",
  "detection_ratio": "14/71",
  "malicious_count": 14,
  "suspicious_count": 0,
  "times_submitted": 1,
  "sha256": "ab5a5aa399949370a99cfc953d9e93a11c7a5c16623f9ce3b94da126e3c9bd49"
}
```

### Response Fields

| Field | Description |
|---|---|
| `detection_ratio` | Engines that flagged it out of total engines scanned e.g. `14/71` |
| `malicious_count` | Number of engines that flagged the file as malicious |
| `suspicious_count` | Number of engines that flagged the file as suspicious |
| `times_submitted` | How many times this file has been uploaded to VirusTotal |
| `sha256` | SHA256 hash of the file |

---

## Testing

The easiest way to test is through the auto-generated docs page. With the server running, open:
```
http://localhost:8000/docs
```
From there you can upload files and see live results without any extra tools.

**For Malware Bazaar samples:**
- Upload the `.zip` file in the `file` field
- Enter `infected` in the `password` field
- Click Execute and watch the terminal for polling status updates

---

## For Teammates

Call the `/scan` endpoint and read these fields from the JSON response:

| Teammate | Field to use |
|---|---|
| Hash checker | `sha256` |
| Report module | `detection_ratio`, `times_submitted` |
| Phishing link checker | `malicious_count`, `suspicious_count` |

---

## File Structure

```
virustotal-module/
├── virustotal.py     ← all scanning logic lives here
├── .env              ← your API key (never commit this)
├── .gitignore        ← keeps .env out of GitHub
└── requirements.txt  ← Python packages needed
```

---

## Notes

- Scans take **1–3 minutes** — the module polls every 15 seconds automatically
- The free VT API allows **4 requests/minute** and **500/day** — rate limit errors are handled automatically with a 60 second backoff
- Always work with malware samples **inside your VM only** — never copy them to your host machine