from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import FileResponse
from plugins.vt_scanner import hash_search, vt_upload, vt_report, url_search, large_file_upload_url,  get_large_file_upload_url, upload_large_file
from typing import Dict, List, Optional
import urllib.parse
import io
import hashlib
import shutil
import os
import time
import asyncio
from pathlib import Path
from dotenv import load_dotenv

enviroment_file_path = Path('./env/.env')
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

        upload_response = vt_upload(file_path)
        time.sleep(5) 
        
        if 'data' in upload_response and 'id' in upload_response['data']:
            analysis_id = upload_response['data']['id']
            while True:
                result = vt_report(analysis_id)
                if result.get('data', {}).get('attributes', {}).get('status') == 'completed':
                    return result
                time.sleep(6)  
        else:
            raise HTTPException(status_code=500, detail="Failed to get analysis ID from upload response.")
        return upload_response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan_url_vt/", response_model=Dict, description="Scan a URL in VirusTotal", tags=["VirusTotal"])
async def scan_url_vt(url: str):
    response = url_search(url)
    return response

@app.get("/hash_search_vt/", response_model=Dict, description="Search for a hash in VirusTotal", tags=["VirusTotal"])
async def hash_search_vt(hash: str):
    response = hash_search(hash)
    return response

@app.post("/upload_large_file", description="Upload a large file to VirusTotal")
async def upload_large_file_vt(file: UploadFile = File(...)):
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        upload_url_response = get_large_file_upload_url()
        upload_url = upload_url_response.get("data")
        
        if not upload_url:
            raise HTTPException(status_code=500, detail="Failed to get upload URL.") 
        response = upload_large_file(file_path, upload_url)
        if 'id' in response.get('data', {}):
            analysis_id = response['data']['id']
            while True:
                result = vt_report(analysis_id)
                if result.get('data', {}).get('attributes', {}).get('status') == 'completed':
                    return result
                time.sleep(10)
        else:
            raise HTTPException(status_code=500, detail="Failed to get analysis ID.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
