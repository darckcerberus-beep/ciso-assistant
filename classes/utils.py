#!/usr/bin/env python3
import requests
import urllib3
import json
import yaml as pyml


from typing import Optional, Dict, Any, List, Set
from keys import API_TOKEN, BASE_URL

# Suppress insecure request warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {"Authorization": f"Token {API_TOKEN}", "Content-Type": "application/json"}

def load_yaml_file(yaml_file: str) -> dict:
    with open(yaml_file, 'r') as f:
        return pyml.safe_load(f)

def get_return(endpoint: str, method: str = "GET", payload: Optional[Dict] = None, params: Optional[Dict] = None) -> Any:
    """Effectue un appel API et retourne la réponse."""
    url = endpoint if endpoint.startswith("http") else f"{BASE_URL.rstrip('/')}/{endpoint.lstrip('/')}"
    try:
        response = requests.request(method, url, json=payload, params=params, headers=HEADERS, verify=False)
        if response.status_code == 400:
            print(f"[!] Error 400 on {endpoint}: {response.text}")
            return {"error": 400, "details": response.json()}
        if response.status_code == 404:
            return {"error": 404}
        response.raise_for_status()
        return response.json() if response.status_code != 204 else True
    except Exception as e:
        print(f"[!] API Error on {endpoint}: {e}")
        return None

def get_all_results(endpoint: str, params: Optional[Dict] = None) -> List[Dict]:
    """Récupère tous les résultats paginés d'un endpoint."""
    results = []
    current_url = endpoint
    first_run = True
    while current_url:
        data = get_return(current_url, params=params) if first_run else get_return(current_url)
        first_run = False
        if not data or not isinstance(data, dict):
            break
        results.extend(data.get("results", []))
        current_url = data.get("next")
    return results