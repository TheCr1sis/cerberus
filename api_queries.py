import requests
import os
from dotenv import load_dotenv


# Function to reload the .env file into the environment
def reload_env():
    load_dotenv(dotenv_path=".env", override=True)


# Function to query VirusTotal
def query_virustotal(hash_value):
    reload_env()
    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        return {"error": "VirusTotal API key not set"}

    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
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