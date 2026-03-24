import os
import time
import traceback
import httpx
from fastapi import FastAPI, UploadFile, File, HTTPException, Form, Request
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from typing import Optional

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": VT_API_KEY}

app = FastAPI()

print(f"API Key loaded: {'YES' if VT_API_KEY else 'NO - KEY IS MISSING'}")


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    traceback.print_exc()
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc)}
    )


@app.post("/scan")
async def scan_file(
    file: UploadFile = File(...),
    password: Optional[str] = Form(default=None)
):
    file_bytes = await file.read()

    form_data = {}
    if password:
        form_data["password"] = password

    # Generous timeouts for VM environments
    timeout_config = httpx.Timeout(
        connect=30.0,
        write=300.0,    # 5 minutes to upload
        read=120.0,
        pool=30.0
    )

    async with httpx.AsyncClient(timeout=timeout_config) as client:
        upload_response = await client.post(
            f"{VT_BASE_URL}/files",
            headers=HEADERS,
            files={"file": (file.filename, file_bytes)},
            data=form_data,
        )

    if upload_response.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"VirusTotal upload failed: {upload_response.text}"
        )

    analysis_id = upload_response.json()["data"]["id"]

    result = await poll_analysis(analysis_id)

    return extract_report_data(result, file.filename)


async def poll_analysis(analysis_id: str, max_attempts: int = 20) -> dict:
    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
        for attempt in range(max_attempts):
            response = await client.get(
                f"{VT_BASE_URL}/analyses/{analysis_id}",
                headers=HEADERS,
            )

            if response.status_code == 429:
                print(f"Rate limited by VT. Waiting 60 seconds...")
                time.sleep(60)
                continue

            if response.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail=f"VT polling failed: {response.text}"
                )

            data = response.json()
            status = data["data"]["attributes"]["status"]

            print(f"Attempt {attempt + 1}: scan status = '{status}'")

            if status == "completed":
                return data

            time.sleep(15)

    raise HTTPException(
        status_code=504,
        detail="Scan timed out — VT took too long to respond"
    )


def extract_report_data(vt_response: dict, filename: str) -> dict:
    attrs = vt_response["data"]["attributes"]
    stats = attrs.get("stats", {})

    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless   = stats.get("harmless", 0)

    total_engines = malicious + suspicious + undetected + harmless
    detection_ratio = f"{malicious}/{total_engines}" if total_engines else "0/0"

    # Try to get sha256 from VT response first,
    # if empty, parse it from the filename (Malware Bazaar naming convention)
    sha256 = attrs.get("sha256", "")
    if not sha256:
        name_without_ext = filename.rsplit(".", 1)[0]  # removes .zip
        if len(name_without_ext) == 64:  # sha256 is always 64 characters
            sha256 = name_without_ext

    return {
        "filename":         filename,
        "status":           "completed",
        "detection_ratio":  detection_ratio,
        "malicious_count":  malicious,
        "suspicious_count": suspicious,
        "times_submitted":  attrs.get("times_submitted", 1),
        "sha256":           sha256,
    }