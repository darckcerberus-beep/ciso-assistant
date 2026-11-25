import copy
import logging
import json
import os
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
_LOG_LEVEL_ENV = os.getenv("LOG_LEVEL", "WARNING").upper()
_INITIAL_LOG_LEVEL = getattr(logging, _LOG_LEVEL_ENV, logging.WARNING)

logging.basicConfig(
    level=_INITIAL_LOG_LEVEL,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    force=True,
)
LOGGER.setLevel(_INITIAL_LOG_LEVEL)


def set_log_level(level: int | str) -> None:
    """Set the logging level dynamically for the root logger and module logger.

    Args:
        level: Integer logging level (e.g. logging.WARNING) or level name string (e.g. 'INFO', 'WARNING').
    """
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.WARNING)
    logging.getLogger().setLevel(level)
    LOGGER.setLevel(level)



def load_yaml_file(yaml_file: str | Path) -> dict[str, Any]:
    """Load and parse a YAML file from disk, automatically resolving common objects if declared.
    
    Args:
        yaml_file: Path to the YAML file to load
        
    Returns:
        Parsed YAML content as a dictionary
        
    Example:
        config = load_yaml_file("config.yml")
    """
    LOGGER.debug(f"Loading YAML file: {yaml_file}")
    filepath = Path(yaml_file)
    try:
        with open(filepath, "r", encoding="utf-8") as file:
            result = pyml.safe_load(file) or {}
        LOGGER.debug(f"Successfully loaded YAML file: {yaml_file}")

        if isinstance(result, dict) and "common_objects_file" in result:
            common_rel = result["common_objects_file"]
            candidate_paths = [
                filepath.parent / common_rel,
                Path(common_rel),
                Path(__file__).resolve().parent.parent / common_rel,
                Path.cwd() / common_rel,
            ]
            common_path = next((p for p in candidate_paths if p.exists() and p.is_file()), None)
            if common_path:
                with open(common_path, "r", encoding="utf-8") as cf:
                    common_data = pyml.safe_load(cf) or {}
                common_objects = common_data.get("objects", {})
                target_objects = result.setdefault("objects", {})
                framework_ref = result.get("ref_id", "")

                for key in ["risk_matrix", "threats", "vulnerabilities", "reference_controls"]:
                    if key in common_objects and key not in target_objects:
                        target_objects[key] = copy.deepcopy(common_objects[key])

                if "risk_scenarios" in common_objects and "risk_scenarios" not in target_objects:
                    scenarios = copy.deepcopy(common_objects["risk_scenarios"])
                    framework_obj = target_objects.get("framework", {})
                    req_nodes_list = framework_obj.get("requirement_nodes", [])
                    req_nodes_by_urn = {rn.get("urn"): rn for rn in req_nodes_list if rn.get("urn")}
                    req_nodes_by_ref = {rn.get("ref_id"): rn for rn in req_nodes_list if rn.get("ref_id")}

                    filtered_scenarios = []
                    for sc in scenarios:
                        allowed_fw = sc.pop("frameworks", None)
                        if allowed_fw and framework_ref and framework_ref not in allowed_fw:
                            continue

                        if framework_ref:
                            if "urn" in sc and isinstance(sc["urn"], str):
                                urn_parts = sc["urn"].split(":")
                                if len(urn_parts) >= 5 and urn_parts[-2] != framework_ref:
                                    urn_parts[-2] = framework_ref
                                    sc["urn"] = ":".join(urn_parts)
                            for lh_key in ("likelihood", "impact"):
                                if lh_key in sc and sc[lh_key]:
                                    old_urn = sc[lh_key]
                                    node_ref = old_urn.rsplit(":", 1)[-1]
                                    adapted_urn = f"urn:intuitem:risk:req_node:{framework_ref}:{node_ref}"
                                    if adapted_urn in req_nodes_by_urn:
                                        sc[lh_key] = adapted_urn
                                    elif node_ref in req_nodes_by_ref:
                                        sc[lh_key] = req_nodes_by_ref[node_ref].get("urn", adapted_urn)
                                    elif old_urn in req_nodes_by_urn:
                                        sc[lh_key] = old_urn
                                    else:
                                        sc[lh_key] = adapted_urn

                        filtered_scenarios.append(sc)

                    target_objects["risk_scenarios"] = filtered_scenarios

        return result
    except FileNotFoundError:
        LOGGER.error(f"YAML file not found: {yaml_file}")
        raise
    except Exception as e:
        LOGGER.error(f"Error loading YAML file {yaml_file}: {e}")
        raise


def load_json_file(json_file: str) -> dict[str, Any]:
    """Load and parse a JSON file from disk.

    Args:
        json_file: Path to the JSON file to load

    Returns:
        Parsed JSON content as a dictionary
    """
    LOGGER.debug(f"Loading JSON file: {json_file}")
    try:
        with open(json_file, "r", encoding="utf-8") as file:
            result = json.load(file) or {}
        LOGGER.debug(f"Successfully loaded JSON file: {json_file}")
        return result
    except FileNotFoundError:
        LOGGER.error(f"JSON file not found: {json_file}")
        raise
    except Exception as e:
        LOGGER.error(f"Error loading JSON file {json_file}: {e}")
        raise


# Build default authentication headers
HEADERS = {
    "Authorization": f"Token {API_TOKEN}",
    "Content-Type": "application/json",
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
    log_errors: bool = True,
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
            if log_errors:
                try:
                    serialized_payload = json.dumps(payload, ensure_ascii=False)
                except TypeError:
                    serialized_payload = repr(payload)
                try:
                    serialized_params = json.dumps(params, ensure_ascii=False)
                except TypeError:
                    serialized_params = repr(params)
                LOGGER.error(
                    "Error 400 on %s: %s | params=%s | payload=%s",
                    endpoint,
                    response.text,
                    serialized_params,
                    serialized_payload,
                )
            return {"error": 400, "details": response.json()}

        if response.status_code == 403:
            if log_errors:
                LOGGER.warning(f"Access forbidden (403) on {endpoint}: {response.text}")
            try:
                details = response.json()
            except Exception:
                details = response.text
            return {"error": 403, "details": details}

        if response.status_code == 401:
            if log_errors:
                LOGGER.error(f"Unauthorized (401) on {endpoint}: {response.text}")
            try:
                details = response.json()
            except Exception:
                details = response.text
            return {"error": 401, "details": details}

        if response.status_code == 404:
            if log_errors:
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


def download_file(endpoint: str, target_path: str | Path, params: dict[str, Any] | None = None) -> bool:
    """Download binary or streamed file from an API endpoint to disk.

    Args:
        endpoint: API endpoint (e.g. '/api/serdes/dump-db/')
        target_path: Destination file path on disk
        params: Optional query parameters

    Returns:
        True if successfully downloaded, False otherwise
    """
    url = endpoint if endpoint.startswith("http") else f"{BASE_URL.rstrip('/')}/{endpoint.lstrip('/')}"
    target_path = Path(target_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    LOGGER.info(f"Downloading from {endpoint} to {target_path}...")
    try:
        response = requests.get(
            url,
            params=params,
            headers=HEADERS,
            verify=False,
            stream=True,
        )
        response.raise_for_status()
        with open(target_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=65536):
                if chunk:
                    f.write(chunk)
        LOGGER.info(f"Successfully downloaded {target_path.stat().st_size} bytes to {target_path}")
        return True
    except Exception:
        LOGGER.exception(f"Failed to download file from {endpoint}")
        return False


def upload_file(
    endpoint: str,
    file_path: str | Path,
    field_name: str = "backup",
    extra_data: dict[str, Any] | None = None,
) -> dict[str, Any] | bool:
    """Upload a file using multipart form-data to an API endpoint.

    Args:
        endpoint: API endpoint (e.g. '/api/serdes/load-backup/')
        file_path: Source file path on disk
        field_name: Form field name for file (default: 'backup')
        extra_data: Optional form data fields

    Returns:
        Response dict or True if successful, None/error dict on failure
    """
    url = endpoint if endpoint.startswith("http") else f"{BASE_URL.rstrip('/')}/{endpoint.lstrip('/')}"
    file_path = Path(file_path)
    if not file_path.exists():
        LOGGER.error(f"File not found for upload: {file_path}")
        return {"error": 404, "details": f"File not found: {file_path}"}

    # For multipart uploads, exclude 'Content-Type: application/json' so requests sets boundary
    upload_headers = {k: v for k, v in HEADERS.items() if k.lower() != "content-type"}

    LOGGER.info(f"Uploading {file_path} to {endpoint} (field={field_name})...")
    try:
        with open(file_path, "rb") as f:
            files = {field_name: (file_path.name, f)}
            response = requests.post(
                url,
                files=files,
                data=extra_data,
                headers=upload_headers,
                verify=False,
            )

        if response.status_code == 400:
            LOGGER.error(f"Error 400 uploading to {endpoint}: {response.text}")
            try:
                return {"error": 400, "details": response.json()}
            except Exception:
                return {"error": 400, "details": response.text}

        response.raise_for_status()
        if response.status_code == 204:
            return True
        try:
            return response.json()
        except Exception:
            return True
    except Exception:
        LOGGER.exception(f"Failed to upload file to {endpoint}")
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


_DISCOVERED_FRAMEWORKS_CACHE: list[dict[str, Any]] | None = None


def discover_framework_catalog(yml_dir: str | Path | None = None) -> list[dict[str, Any]]:
    """Dynamically discover assessment framework YAML files in the YML directory without hardcoding filenames."""
    global _DISCOVERED_FRAMEWORKS_CACHE
    if yml_dir is None and _DISCOVERED_FRAMEWORKS_CACHE is not None:
        return list(_DISCOVERED_FRAMEWORKS_CACHE)

    repo_root = Path(__file__).resolve().parent.parent
    if yml_dir is None:
        search_dir = Path("YML") if Path("YML").exists() else repo_root / "YML"
    else:
        search_dir = Path(yml_dir)

    if not search_dir.exists():
        return []

    app_fw_order: list[str] = []
    td_dir = Path("test_data") if Path("test_data").exists() else repo_root / "test_data"
    if td_dir.exists():
        app_entries = []
        for td_file in sorted(td_dir.glob("*.yml")) + sorted(td_dir.glob("*.yaml")):
            try:
                with open(td_file, "r", encoding="utf-8") as f:
                    td_data = pyml.safe_load(f)
                if isinstance(td_data, dict) and isinstance(td_data.get("application"), dict):
                    app_entries.append(td_data["application"])
            except Exception:
                pass
        app_entries.sort(key=lambda a: (a.get("order", 999), a.get("name", "")))
        for app in app_entries:
            fw_r = str(app.get("framework_ref", "")).strip()
            if fw_r and fw_r not in app_fw_order:
                app_fw_order.append(fw_r)

    catalog: list[dict[str, Any]] = []
    yaml_files = sorted(search_dir.glob("*.yml")) + sorted(search_dir.glob("*.yaml"))
    for yf in yaml_files:
        try:
            with open(yf, "r", encoding="utf-8") as f:
                data = pyml.safe_load(f)
            if not isinstance(data, dict):
                continue
            objects = data.get("objects")
            if not isinstance(objects, dict) or not isinstance(objects.get("framework"), dict):
                continue
            if "audit" not in data and "criticality_mapping" not in data and "test_metadata" not in data:
                continue

            fw_obj = objects["framework"]
            ref_id = str(data.get("ref_id") or fw_obj.get("ref_id") or yf.stem).strip()
            name = str(data.get("name") or fw_obj.get("name") or ref_id).strip()
            desc = str(fw_obj.get("description") or data.get("description") or "").strip()
            try:
                rel_path = str(yf.relative_to(Path.cwd()))
            except ValueError:
                try:
                    rel_path = str(yf.relative_to(repo_root))
                except ValueError:
                    rel_path = f"YML/{yf.name}"

            catalog.append({
                "ref_id": ref_id,
                "name": name,
                "yaml_path": rel_path,
                "description": desc,
            })
        except Exception:
            pass

    def _sort_key(item: dict[str, Any]) -> tuple[int, str]:
        r = item.get("ref_id", "")
        idx = app_fw_order.index(r) if r in app_fw_order else len(app_fw_order)
        return (idx, r)

    catalog.sort(key=_sort_key)
    if yml_dir is None:
        _DISCOVERED_FRAMEWORKS_CACHE = list(catalog)
    return catalog


def get_default_framework_yaml_path() -> str:
    """Return the dynamically discovered default framework YAML path."""
    catalog = discover_framework_catalog()
    if catalog:
        return str(catalog[0]["yaml_path"])
    repo_root = Path(__file__).resolve().parent.parent
    yml_dir = Path("YML") if Path("YML").exists() else repo_root / "YML"
    candidates = sorted(yml_dir.glob("*.yml")) + sorted(yml_dir.glob("*.yaml")) if yml_dir.exists() else []
    return str(candidates[0]) if candidates else ""


def initialize_data_objects() -> dict[str, Any]:
    """Instantiate all required dictionaries and framework objects used in the workflow."""
    from classes.audits.compliance import ComplianceAssessmentDict
    from classes.audits.entity_assessment import EntityAssessmentDict
    from classes.audits.finding import FindingDict, FindingsAssessmentDict
    from classes.audits.requirement_assignment import RequirementAssignmentDict
    from classes.audits.requirement_assessment import RequirementAssessmentDict
    from classes.controls.applied import AppliedControlDict
    from classes.controls.reference import ReferenceControlDict
    from classes.core.framework import FrameworkDict, LibraryFile
    from classes.core.risk import RiskAssessmentDict, RiskMatrixDict, RiskScenarioDict, ThreatDict, VulnerabilityDict
    from classes.core.user import UserDict
    from classes.organization.asset import AssetDict
    from classes.organization.entity import EntityDict
    from classes.organization.perimeter import PerimeterDict

    requirement_assessment_dict = RequirementAssessmentDict()
    compliance_assessment_dict = ComplianceAssessmentDict()
    requirement_assignment_dict = RequirementAssignmentDict()
    perimeter_dict = PerimeterDict()
    asset_dict = AssetDict()
    framework_dict = FrameworkDict()
    reference_control_dict = ReferenceControlDict()
    applied_control_dict = AppliedControlDict()
    risk_assessment_dict = RiskAssessmentDict()
    risk_scenario_dict = RiskScenarioDict()
    user_dict = UserDict()
    library_file = LibraryFile(get_default_framework_yaml_path())
    risk_matrix_dict = RiskMatrixDict()
    entity_dict = EntityDict()
    entity_assessment_dict = EntityAssessmentDict()
    findings_assessment_dict = FindingsAssessmentDict()
    finding_dict = FindingDict()
    threat_dict = ThreatDict()
    vulnerability_dict = VulnerabilityDict()

    return {
        "requirement_assessment_dict": requirement_assessment_dict,
        "compliance_assessment_dict": compliance_assessment_dict,
        "requirement_assignment_dict": requirement_assignment_dict,
        "perimeter_dict": perimeter_dict,
        "asset_dict": asset_dict,
        "framework_dict": framework_dict,
        "reference_control_dict": reference_control_dict,
        "applied_control_dict": applied_control_dict,
        "risk_assessment_dict": risk_assessment_dict,
        "risk_scenario_dict": risk_scenario_dict,
        "user_dict": user_dict,
        "library_file": library_file,
        "risk_matrix_dict": risk_matrix_dict,
        "entity_dict": entity_dict,
        "entity_assessment_dict": entity_assessment_dict,
        "findings_assessment_dict": findings_assessment_dict,
        "finding_dict": finding_dict,
        "threat_dict": threat_dict,
        "vulnerability_dict": vulnerability_dict,
    }


def capture_counts(data: dict) -> dict[str, int]:
    """Capture counts of key objects from the initialized data dictionary.

    Args:
        data: The data dictionary returned by `initialize_data_objects()`.

    Returns:
        A mapping of metric name -> integer count.
    """
    counts = {
        "assets": len(data["asset_dict"].get_assets()),
        "compliance_assessments": len(data["compliance_assessment_dict"].get_compliance_assessments()),
        "entity_assessments": len(data["entity_assessment_dict"].get_entity_assessments()),
        "applied_controls": len(data["applied_control_dict"].get_controls()),
        "risk_assessments": len(data["risk_assessment_dict"].get_risk_assessments()),
        "risk_scenarios": len(data["risk_scenario_dict"].get_risk_scenarios()),
        "requirement_assessments": len(data["compliance_assessment_dict"].requirement_assessments.get_requirement_assessments()),
        "requirement_assignments": len(data["compliance_assessment_dict"].requirement_assignments.get_requirement_assignments()),
    }
    if "findings_assessment_dict" in data:
        counts["findings_assessments"] = len(data["findings_assessment_dict"].get_findings_assessments())
    if "finding_dict" in data:
        counts["findings"] = len(data["finding_dict"].get_findings())
    if "security_exception_dict" in data:
        counts["security_exceptions"] = len(data["security_exception_dict"].get_security_exceptions())
    return counts



def print_run_summary(initial_counts: dict[str, int], final_counts: dict[str, int]) -> None:
    """Log a concise summary showing final counts and deltas from initial counts.

    Args:
        initial_counts: Mapping of metric -> initial count
        final_counts: Mapping of metric -> final count
    """
    log("Run summary:")
    for key in final_counts:
        delta = final_counts[key] - initial_counts.get(key, 0)
        if key == "entity_assessments":
            if delta > 0:
                change_label = f"created: +{delta}"
            elif delta < 0:
                change_label = f"removed: {delta}"
            else:
                change_label = "created: +0"
            log(f"- {key}: {final_counts[key]} ({change_label})")
            continue

        log(f"- {key}: {final_counts[key]} (changed: {delta:+d})")


def format_audit_name(
    app_name: str,
    framework_name: str | None = None,
    framework_ref: str | None = None,
) -> str:
    """Format compliance assessment (audit) display name according to enterprise convention:
    'Assessment of <app_name> with <framework_label> framework'.

    Examples:
        format_audit_name("Mirakl", "Application Security Assessment Framework (AppSec)")
        -> "Assessment of Mirakl with AppSec framework"

        format_audit_name("App-Secure-Core", "Multi-level DPP")
        -> "Assessment of App-Secure-Core with Multi-level DPP framework"

        format_audit_name("Mirakl", "AppSec")
        -> "Assessment of Mirakl with AppSec framework"
    """
    app_clean = (app_name or "").strip()
    fw_str = (framework_name or framework_ref or "").strip()

    if not fw_str:
        return f"Assessment of {app_clean}" if app_clean else "Compliance Assessment"

    # Extract short acronym/name in trailing parentheses if present, e.g.
    # "Application Security Assessment Framework (AppSec)" -> "AppSec"
    # "Application Security Assessment Framework (AppSec - Manual IG)" -> "AppSec - Manual IG"
    import re
    match = re.search(r'\(([^)]+)\)\s*$', fw_str)
    if match:
        fw_label = match.group(1).strip()
    else:
        if framework_ref and framework_ref.lower() in ("appsec", "appsec_manual") and "appsec" in fw_str.lower():
            fw_label = "AppSec"
        else:
            fw_label = fw_str

    # Ensure "framework" is appended cleanly without duplication
    if not fw_label.lower().endswith("framework"):
        fw_label = f"{fw_label} framework"

    if not app_clean:
        return f"Assessment with {fw_label}"

    return f"Assessment of {app_clean} with {fw_label}"
