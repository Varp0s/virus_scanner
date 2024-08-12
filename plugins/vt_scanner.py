import requests
from typing import Dict
from pathlib import Path
from dotenv import load_dotenv
import os

# Load the environment variables
enviroment_file_path = Path('./env/.env')
load_dotenv(dotenv_path=enviroment_file_path)

VT_API_KEY = os.getenv("VT_API_KEY")
VT_UPLOAD_URL = os.getenv("VT_UPLOAD_URL")
VT_API_URL = os.getenv("VT_API_URL")
VT_ANALYSIS_URL = os.getenv("VT_ANALYSIS_URL")

def vt_upload(file_path: str) -> Dict:
    url = VT_UPLOAD_URL
    headers = {
        'x-apikey': VT_API_KEY
    }
    with open(file_path, 'rb') as file:
        files = {'file': file}
        try:
            response = requests.post(url, headers=headers, files=files)
            response.raise_for_status() 
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            return {}

def vt_report(analysis_id: str) -> Dict:
    url = f"{VT_ANALYSIS_URL}/{analysis_id}"
    headers = {
        'x-apikey': VT_API_KEY
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return {}

def hash_search(hash: str) -> Dict:
    url = f"{VT_UPLOAD_URL}/{hash}"
    headers = {
        'x-apikey': VT_API_KEY
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return {}
