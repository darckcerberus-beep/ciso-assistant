#!/usr/bin/env python3
import logging
from typing import Any, Dict, List, Optional

import requests
import urllib3
import yaml as pyml

from keys import API_TOKEN, BASE_URL

# Suppress warnings for self-signed certificates used by the internal API.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Default authentication headers shared by all API requests.
HEADERS = {
    "Authorization": f"Token {API_TOKEN}",
    "Content-Type": "application/json",
}

LOGGER = logging.getLogger(__name__)


def log(message: str, level: int = logging.INFO) -> None:
    """Write a utility log message.

    Example:
        log("Request completed")
        log("Request failed", level=logging.ERROR)
    """
    LOGGER.log(level, message)


def load_yaml_file(yaml_file: str) -> Dict[str, Any]:
    """Load and parse a YAML file from disk."""
    with open(yaml_file, "r", encoding="utf-8") as file:
        return pyml.safe_load(file) or {}


def get_return(
    endpoint: str,
    method: str = "GET",
    payload: Optional[Dict[str, Any]] = None,
    params: Optional[Dict[str, Any]] = None,
) -> Any:
    """Execute an API request and return the JSON payload."""
    # Build the complete URL when the caller provides a relative endpoint.
    url = endpoint if endpoint.startswith("http") else f"{BASE_URL.rstrip('/')}/{endpoint.lstrip('/')}"

    try:
        response = requests.request(
            method,
            url,
            json=payload,
            params=params,
            headers=HEADERS,
            verify=False,
        )

        if response.status_code == 400:
            LOGGER.error("Error 400 on %s: %s", endpoint, response.text)
            return {"error": 400, "details": response.json()}

        if response.status_code == 404:
            return {"error": 404}

        response.raise_for_status()

        # A 204 response indicates success without a body.
        return response.json() if response.status_code != 204 else True

    except Exception as exc:  # pragma: no cover - logging wrapper for API failures.
        LOGGER.exception("API error on %s: %s", endpoint, exc)
        return None


def get_all_results(endpoint: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Collect all paginated results for a given endpoint."""
    results: List[Dict[str, Any]] = []
    current_url = endpoint
    first_run = True

    while current_url:
        # Apply query params only to the first request; subsequent pages provide them in `next`.
        data = get_return(current_url, params=params) if first_run else get_return(current_url)
        first_run = False

        if not data or not isinstance(data, dict):
            break

        results.extend(data.get("results", []))
        current_url = data.get("next")

    return results