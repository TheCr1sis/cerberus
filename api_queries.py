import requests
import os
from dotenv import load_dotenv


# Function to reload the .env file into the environment
def reload_env():
    load_dotenv(dotenv_path=".env", override=True)

load_dotenv()

# Function to query VirusTotal
def query_virustotal(hash_value):
    reload_env()
    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        return {"error": "VirusTotal API key not set"}

    base_url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": api_key}

    try:
        # Fetch main file report
        file_response = requests.get(f"{base_url}/{hash_value}", headers=headers)
        file_response.raise_for_status()
        file_data = file_response.json()

        # Fetch behavior tab of virustotal analysis
        behavior_response = requests.get(f"{base_url}/{hash_value}/behaviours", headers=headers)
        if behavior_response.status_code == 200:
            behavior_data = behavior_response.json()
        else:
            behavior_data = {"error": "No behavior analysis available"}

        return {
            "file_info": file_data,
            "behavior": behavior_data
        }

    except requests.exceptions.RequestException as e:
        return {"error": f"VirusTotal lookup failed: {str(e)}"}


# Function to query MalwareBazaar by hash
def query_malwarebazaar(hash_value):
    reload_env()
    api_key = os.getenv("MB_AUTH_KEY")

    if not api_key:
        return {"error": "MalwareBazaar API key not set"}

    url = "https://mb-api.abuse.ch/api/v1/"
    headers = {
        "Auth-Key": api_key,
        "User-Agent": "Mozilla/5.0",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    payload = {
        "query": "get_info",
        "hash": hash_value
    }

    try:
        response = requests.post(url, headers=headers, data=payload, timeout=10)

        response.raise_for_status()

        data = response.json()

        if data.get("query_status") == "hash_not_found":
            return {"error": "Hash not found in MalwareBazaar database"}

        return data

    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}

    except ValueError:
        return {"error": "Failed to parse response from MalwareBazaar"}