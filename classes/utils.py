import logging
from pathlib import Path
from typing import Any

import requests
import urllib3
import yaml as pyml

from keys import API_TOKEN, BASE_URL

# Suppress warnings for self-signed certificates used by the internal API.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOGGER = logging.getLogger(__name__)

# Configure logging format and level
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)


def load_yaml_file(yaml_file: str) -> dict[str, Any]:
    """Load and parse a YAML file from disk.
    
    Args:
        yaml_file: Path to the YAML file to load
        
    Returns:
        Parsed YAML content as a dictionary
        
    Example:
        config = load_yaml_file("config.yml")
    """
    LOGGER.debug(f"Loading YAML file: {yaml_file}")
    try:
        with open(yaml_file, "r", encoding="utf-8") as file:
            result = pyml.safe_load(file) or {}
        LOGGER.debug(f"Successfully loaded YAML file: {yaml_file}")
        return result
    except FileNotFoundError:
        LOGGER.error(f"YAML file not found: {yaml_file}")
        raise
    except Exception as e:
        LOGGER.error(f"Error loading YAML file {yaml_file}: {e}")
        raise


# Load settings from the settings YAML file
_settings_path = Path(__file__).parent.parent / "YML" / "settings.yml"
_settings = load_yaml_file(str(_settings_path))

# Build default authentication headers from settings
_headers_config = _settings.get("api", {}).get("headers", {})
HEADERS = {
    "Authorization": f"Token {API_TOKEN}",
    **_headers_config,
}

# Simple in-process cache for paginated GET results to avoid repeated API calls
_get_all_results_cache: dict[str, list[dict[str, Any]]] = {}


def log(message: str, level: int = logging.INFO) -> None:
    """Write a utility log message with configurable level.
    
    Logging levels guide:
    - DEBUG (10): Detailed information for diagnosing problems. Used for detailed traces of function execution.
      Example: log(f"Processing item {item_id}", level=logging.DEBUG)
      
    - INFO (20): Confirmation that things are working as expected. Used for major function completions.
      Example: log(f"Created compliance assessment with ID {ca_id}", level=logging.INFO)
      
    - WARNING (30): Something unexpected happened or may happen in the future. Used for potentially problematic situations.
      Example: log(f"No compliance assessments found for framework {fw_id}", level=logging.WARNING)
      
    - ERROR (40): A serious problem that prevented the software from doing some function.
      Example: log(f"Failed to create asset: {error}", level=logging.ERROR)
      
    - CRITICAL (50): A serious error that may cause the application to fail.
      Example: log(f"API connection failed: {error}", level=logging.CRITICAL)

    Args:
        message: The log message to write
        level: The logging level (default: logging.INFO)

    Example:
        log("Request completed")
        log("Request failed", level=logging.ERROR)
        log(f"Processing {count} items", level=logging.DEBUG)
    """
    LOGGER.log(level, message)


def get_return(
    endpoint: str,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
) -> Any:
    """Execute an API request and return the JSON payload.
    
    Logs API calls at DEBUG level (request details) and handles errors with ERROR level.
    
    Args:
        endpoint: API endpoint (relative or absolute URL)
        method: HTTP method (GET, POST, PATCH, DELETE, etc.)
        payload: Request body for POST/PATCH requests
        params: Query parameters for the request
        
    Returns:
        Parsed JSON response or error dict
        
    Example:
        response = get_return("/api/compliance-assessments/")
        response = get_return("/api/assets/", method="POST", payload={"name": "Asset1"})
    """
    # Build the complete URL when the caller provides a relative endpoint.
    url = endpoint if endpoint.startswith("http") else f"{BASE_URL.rstrip('/')}/{endpoint.lstrip('/')}"

    LOGGER.debug(f"API request: {method} {url} with params={params}, payload={'<payload>' if payload else 'None'}")
    
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
            LOGGER.error(f"Error 400 on {endpoint}: {response.text}")
            return {"error": 400, "details": response.json()}

        if response.status_code == 404:
            LOGGER.warning(f"Resource not found (404) on {endpoint}")
            return {"error": 404}

        response.raise_for_status()

        # A 204 response indicates success without a body.
        result = response.json() if response.status_code != 204 else True
        LOGGER.debug(f"API response: {method} {endpoint} returned status {response.status_code}")
        return result

    except Exception:  # pragma: no cover - logging wrapper for API failures.
        LOGGER.exception(f"API error on {endpoint}")
        return None


def get_all_results(endpoint: str, params: dict[str, Any] | None = None, force_reload: bool = False) -> list[dict[str, Any]]:
    """Collect all paginated results for a given endpoint.
    
    Automatically handles pagination by following the 'next' link in responses.
    Logs at INFO level when pagination is detected.
    
    Args:
        endpoint: API endpoint to query
        params: Query parameters for the first request
        
    Returns:
        List of all results from all pages
        
    Example:
        all_assessments = get_all_results("/api/compliance-assessments/")
    """
    cache_key = endpoint
    if params:
        try:
            # Build a stable representation of params for caching
            params_key = ";".join(f"{k}={v}" for k, v in sorted(params.items()))
            cache_key = f"{endpoint}?{params_key}"
        except Exception:
            cache_key = endpoint

    if not force_reload and cache_key in _get_all_results_cache:
        LOGGER.debug(f"Using cached results for {cache_key}")
        return list(_get_all_results_cache[cache_key])

    LOGGER.info(f"Fetching all results from {endpoint}")
    results: list[dict[str, Any]] = []
    current_url = endpoint
    first_run = True
    page_count = 0

    while current_url:
        page_count += 1
        # Apply query params only to the first request; subsequent pages provide them in `next`.
        data = get_return(current_url, params=params) if first_run else get_return(current_url)
        first_run = False

        if not data or not isinstance(data, dict):
            LOGGER.debug(f"No data returned from {current_url}")
            break

        page_results = data.get("results", [])
        results.extend(page_results)
        LOGGER.debug(f"Page {page_count}: Retrieved {len(page_results)} results from {endpoint}")
        
        current_url = data.get("next")
        if current_url:
            LOGGER.debug(f"Pagination detected, fetching next page from: {current_url}")

    LOGGER.info(f"Completed fetching all results from {endpoint}: {len(results)} total results across {page_count} pages")
    _get_all_results_cache[cache_key] = list(results)
    return results


def clear_get_all_results_cache() -> None:
    """Clear the in-memory cache used by `get_all_results`.

    Callers that need to ensure fresh reads across the process can call this helper.
    """
    _get_all_results_cache.clear()


def capture_counts(data: dict) -> dict[str, int]:
    """Capture counts of key objects from the initialized data dictionary.

    Args:
        data: The data dictionary returned by `initialize_data_objects()` in `main.py`.

    Returns:
        A mapping of metric name -> integer count.
    """
    return {
        "assets": len(data["asset_dict"].get_assets()),
        "compliance_assessments": len(data["compliance_assessment_dict"].get_compliance_assessments()),
        "applied_controls": len(data["applied_control_dict"].get_controls()),
        "risk_assessments": len(data["risk_assessment_dict"].get_risk_assessments()),
        "risk_scenarios": len(data["risk_scenario_dict"].get_risk_scenarios()),
        "requirement_assessments": len(data["compliance_assessment_dict"].requirement_assessments.get_requirement_assessments()),
        "requirement_assignments": len(data["compliance_assessment_dict"].requirement_assignments.get_requirement_assignments()),
    }


def print_run_summary(initial_counts: dict[str, int], final_counts: dict[str, int]) -> None:
    """Log a concise summary showing final counts and deltas from initial counts.

    Args:
        initial_counts: Mapping of metric -> initial count
        final_counts: Mapping of metric -> final count
    """
    log("Run summary:")
    for key in final_counts:
        delta = final_counts[key] - initial_counts.get(key, 0)
        log(f"- {key}: {final_counts[key]} (changed: {delta:+d})")