from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import FileResponse
from plugins.vt_scanner import hash_search, vt_upload, vt_report
from typing import Dict, List, Optional
import urllib.parse
import io
import hashlib
import shutil
import os
import time

from pathlib import Path
from dotenv import load_dotenv
enviroment_file_path= Path('./env/.env')
load_dotenv(dotenv_path=enviroment_file_path)

app = FastAPI(
    title="VirusTotal API",
    description="This is a VirusTotal API to upload files and hash search get the report",
    version="0.0.1",
    docs_url="/swagger",
)

UPLOAD_DIR = os.getenv("UPLOAD_DIR")
VT_API_KEY = os.getenv("VT_API_KEY")
VT_UPLOAD_URL = os.getenv("VT_UPLOAD_URL")
VT_ANALYSIS_URL = os.getenv("VT_ANALYSIS_URL")

os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.post("/upload_file_vt/", description="Upload a file to VirusTotal and get the analysis results", tags=["VirusTotal"])
async def upload_file_vt(file: UploadFile = File(...)):
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        # Upload the file and get the analysis ID
        upload_response = vt_upload(file_path)
        time.sleep(2)  # Wait for 5 seconds before checking the analysis
        if 'data' in upload_response and 'id' in upload_response['data']:
            analysis_id = upload_response['data']['id']
            # Wait for the analysis to complete
            while True:
                result = vt_report(analysis_id)
                if result.get('data', {}).get('attributes', {}).get('status') == 'completed':
                    return result
                time.sleep(10)  # Wait for 10 seconds before checking again
        else:
            raise HTTPException(status_code=500, detail="Failed to get analysis ID from upload response.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/hash_search_vt/", response_model=Dict,description="Search for a hash in VirusTotal", tags=["VirusTotal"])
async def hash_search_vt(hash: str):
    response = hash_search(hash)
    return response

