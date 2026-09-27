"""Flask Web Application for CISO Assistant Orchestration and Example Applications Manager.

Provides a full-featured Web UI and REST API mirroring and extending all capabilities of main.py:
- Live Status Dashboard & Inventory (DPP & VDD applications, lifecycle statuses, metrics)
- Example Application Provisioning (all or specific apps with framework validation)
- Interactive Audit Demo Intake (assigning unanswered assessments to users)
- Dynamic Risk Scenario & Applied Control Generation (live UI, profile, or custom YAML answers)
- Existing & Planned Control Linking to Risk Scenarios
- Application Removal and Teardown
- Offline Simulation Studio (4x4 risk matrix visualization, inverse likelihood & impact scoring)
- Disaster Recovery & Backup Management (snapshots, database dumps, inspection, restore, upload/download)
- Legacy Orchestration Pipeline Runner
- Real-time Console Log Streaming via Server-Sent Events (SSE)
"""

import contextlib
from datetime import datetime, timezone
import io
import json
import logging
from pathlib import Path
import sys
import threading
import time
from typing import Any
from collections.abc import Callable
import uuid

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    render_template,
    request,
    send_from_directory,
)
from werkzeug.utils import secure_filename

from classes import utils
from classes.examples_manager import (
    EXAMPLE_FOLDER_NAME,
    FRAMEWORK_CATALOG,
    ExamplesManager,
)
from classes.integrations import import_department_external_entity_model
from classes.organization.domain import criticality_mapping
from tests.test_application_scenarios import ApplicationRiskSimulator

LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Background Task & Real-time Log Streaming Engine
# ---------------------------------------------------------------------------

class TaskLogHandler(logging.Handler):
    """Logging handler that routes formatted log messages into a task's log queue."""

    def __init__(self, callback: Callable[[str], None]):
        super().__init__()
        self.callback = callback
        self.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%H:%M:%S"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            self.callback(msg)
        except Exception:
            self.handleError(record)


class TaskStreamWriter(io.TextIOBase):
    """Stream wrapper redirecting writes to a callback while preserving original stream."""

    def __init__(self, callback: Callable[[str], None], original_stream: io.TextIOBase):
        self.callback = callback
        self.original_stream = original_stream
        self._buffer = ""

    def write(self, s: str) -> int:
        with contextlib.suppress(Exception):
            self.original_stream.write(s)
            self.original_stream.flush()

        self._buffer += s
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            line_clean = line.strip("\r")
            if line_clean:
                self.callback(line_clean)
        return len(s)

    def flush(self) -> None:
        if self._buffer.strip():
            self.callback(self._buffer.strip())
            self._buffer = ""
        with contextlib.suppress(Exception):
            self.original_stream.flush()


class BackgroundTaskManager:
    """Manages asynchronous tasks with real-time log capturing and event notifications."""

    def __init__(self, max_history: int = 50):
        self.max_history = max_history
        self.tasks: dict[str, dict[str, Any]] = {}
        self.events: dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    def create_task(self, name: str, func: Callable[..., Any], *args: Any, **kwargs: Any) -> str:
        """Create and launch a background task."""
        task_id = f"task_{int(time.time())}_{uuid.uuid4().hex[:6]}"
        task_info = {
            "id": task_id,
            "name": name,
            "status": "pending",  # pending, running, completed, failed
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
            "logs": [],
            "result": None,
            "error": None,
            "log_subscribers": [],
        }

        with self._lock:
            self.tasks[task_id] = task_info
            # Prune old tasks if exceeding history
            if len(self.tasks) > self.max_history:
                oldest_id = next(iter(self.tasks))
                if oldest_id != task_id and self.tasks[oldest_id]["status"] in ("completed", "failed"):
                    del self.tasks[oldest_id]

        def _runner():
            task_info["status"] = "running"
            log_queue: list[str] = task_info["logs"]

            def append_log(line: str):
                ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
                entry = f"[{ts}] {line}"
                with self._lock:
                    log_queue.append(entry)
                    for sub in list(task_info["log_subscribers"]):
                        with contextlib.suppress(Exception):
                            sub(entry)

            append_log(f"=== Started: {name} ===")

            stream_writer = TaskStreamWriter(append_log, sys.stdout)
            log_handler = TaskLogHandler(append_log)

            root_logger = logging.getLogger()
            root_logger.addHandler(log_handler)

            try:
                with contextlib.redirect_stdout(stream_writer), contextlib.redirect_stderr(stream_writer):
                    res = func(*args, **kwargs)
                task_info["result"] = res
                task_info["status"] = "completed"
                append_log(f"=== Successfully completed: {name} ===")
            except Exception as e:
                task_info["error"] = str(e)
                task_info["status"] = "failed"
                append_log(f"[ERROR] Task failed: {e}")
                LOGGER.exception("Task %s failed", task_id)
            finally:
                stream_writer.flush()
                root_logger.removeHandler(log_handler)
                task_info["finished_at"] = datetime.now(timezone.utc).isoformat()

        thread = threading.Thread(target=_runner, daemon=True)
        thread.start()
        return task_id

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        """Retrieve task information dictionary."""
        with self._lock:
            info = self.tasks.get(task_id)
            if not info:
                return None
            return {
                "id": info["id"],
                "name": info["name"],
                "status": info["status"],
                "started_at": info["started_at"],
                "finished_at": info["finished_at"],
                "logs": list(info["logs"]),
                "result": info["result"],
                "error": info["error"],
            }

    def list_tasks(self) -> list[dict[str, Any]]:
        """List summary of all tracked tasks."""
        with self._lock:
            return [
                {
                    "id": t["id"],
                    "name": t["name"],
                    "status": t["status"],
                    "started_at": t["started_at"],
                    "finished_at": t["finished_at"],
                    "error": t["error"],
                    "log_count": len(t["logs"]),
                }
                for t in reversed(list(self.tasks.values()))
            ]


TASK_MANAGER = BackgroundTaskManager()


# ---------------------------------------------------------------------------
# App Factory & Routes
# ---------------------------------------------------------------------------

def create_app(test_config: dict[str, Any] | None = None, manager: ExamplesManager | None = None) -> Flask:
    """Create and configure the Flask Web Application."""
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).resolve().parent / "templates"),
        static_folder=str(Path(__file__).resolve().parent / "static"),
    )

    if test_config:
        app.config.update(test_config)

    if manager is None:
        manager = app.config.get("manager") or ExamplesManager()
    app.manager = manager

    # -----------------------------------------------------------------------
    # Web UI Page
    # -----------------------------------------------------------------------

    @app.route("/")
    def index():
        """Render main Web UI dashboard."""
        return render_template(
            "index.html",
            base_url=utils.BASE_URL,
            target_folder=EXAMPLE_FOLDER_NAME,
        )

    # -----------------------------------------------------------------------
    # Status & Inventory Endpoints
    # -----------------------------------------------------------------------

    @app.route("/api/status")
    def api_status():
        """Retrieve deployment status across all applications."""
        wait_sec = float(request.args.get("wait", 0.0))

        connected, conn_msg = manager.test_connection()
        if not connected:
            return jsonify({
                "connected": False,
                "message": conn_msg,
                "base_url": utils.BASE_URL,
                "folder_name": EXAMPLE_FOLDER_NAME,
                "applications": [],
                "installed_frameworks": [],
                "catalog": manager.get_example_applications(),
                "summary": {
                    "total_catalog": len(manager.get_example_applications()),
                    "deployed": 0,
                    "completed_audits": 0,
                    "total_risks": 0,
                    "total_controls": 0,
                    "total_findings": 0,
                },
            })

        if wait_sec > 0:
            time.sleep(wait_sec)

        status_list = manager.get_status(wait_seconds=0)
        installed_fws = manager.get_installed_frameworks()
        catalog_apps = manager.get_example_applications()

        # Compute aggregate metrics
        deployed_apps = [s for s in status_list if s.get("exists")]
        completed_audits = sum(
            1 for s in deployed_apps
            if s.get("audit_answered")
            and (s.get("audit_completion_pct", 0) >= 100 or s.get("compliance_status") == "completed")
        )
        partial_audits = sum(
            1 for s in deployed_apps
            if s.get("answered_requirements_count", 0) > 0 and s.get("audit_completion_pct", 0) < 100
        )
        total_risks = sum(s.get("risk_scenarios_count", 0) for s in deployed_apps)
        total_controls = sum(s.get("applied_controls_count", 0) for s in deployed_apps)
        total_findings = sum(s.get("findings_count", 0) for s in deployed_apps)

        return jsonify({
            "connected": True,
            "message": conn_msg,
            "base_url": utils.BASE_URL,
            "folder_name": EXAMPLE_FOLDER_NAME,
            "applications": status_list,
            "installed_frameworks": installed_fws,
            "catalog": catalog_apps,
            "summary": {
                "total_catalog": len(catalog_apps),
                "deployed": len(deployed_apps),
                "completed_audits": completed_audits,
                "partial_audits": partial_audits,
                "total_risks": total_risks,
                "total_controls": total_controls,
                "total_findings": total_findings,
            },
        })

    @app.route("/api/frameworks")
    def api_frameworks():
        """Retrieve installed and catalog frameworks."""
        installed = manager.get_installed_frameworks()
        return jsonify({
            "installed": installed,
            "catalog": FRAMEWORK_CATALOG,
        })

    @app.route("/api/catalog")
    def api_catalog():
        """Retrieve pre-configured application portfolio catalog."""
        return jsonify(manager.get_example_applications())

    # -----------------------------------------------------------------------
    # Task Management & Log Streaming Endpoints
    # -----------------------------------------------------------------------

    @app.route("/api/tasks")
    def api_tasks():
        """List active and recent background tasks."""
        return jsonify(TASK_MANAGER.list_tasks())

    @app.route("/api/tasks/<task_id>")
    def api_task_status(task_id: str):
        """Get status and logs for a specific task."""
        offset = int(request.args.get("offset", 0))
        info = TASK_MANAGER.get_task(task_id)
        if not info:
            abort(404, description=f"Task '{task_id}' not found.")

        # Return only new logs starting from offset
        logs_slice = info["logs"][offset:]
        return jsonify({
            "id": info["id"],
            "name": info["name"],
            "status": info["status"],
            "started_at": info["started_at"],
            "finished_at": info["finished_at"],
            "logs": logs_slice,
            "total_logs": len(info["logs"]),
            "result": info["result"],
            "error": info["error"],
        })

    @app.route("/api/tasks/<task_id>/stream")
    def api_task_stream(task_id: str):
        """Server-Sent Events (SSE) stream for live task log output."""
        task_info = TASK_MANAGER.tasks.get(task_id)
        if not task_info:
            abort(404, description="Task not found")

        def event_generator():
            sent_idx = 0
            while True:
                with TASK_MANAGER._lock:
                    logs = list(task_info["logs"])
                    status = task_info["status"]
                    result = task_info["result"]
                    error = task_info["error"]

                while sent_idx < len(logs):
                    line = logs[sent_idx]
                    yield f"data: {json.dumps({'line': line, 'index': sent_idx})}\n\n"
                    sent_idx += 1

                if status in ("completed", "failed"):
                    yield f"data: {json.dumps({'done': True, 'status': status, 'result': result, 'error': error})}\n\n"
                    break

                time.sleep(0.2)

        return Response(event_generator(), mimetype="text/event-stream")

    # -----------------------------------------------------------------------
    # Provisioning Endpoints
    # -----------------------------------------------------------------------

    @app.route("/api/provision/all", methods=["POST"])
    def api_provision_all():
        """Provision all 12 example applications in CISO Assistant."""
        def _job():
            example_apps = manager.get_example_applications()
            print(f"Creating all {len(example_apps)} example applications in CISO Assistant...")
            results = []
            for app_entry in example_apps:
                app_fw_ref = app_entry.get("framework_ref")
                app_fw_name = app_entry.get("framework_name")
                matching_fw = manager.find_target_framework(app_fw_ref or app_fw_name)
                if not matching_fw:
                    print(f"---> [SKIPPED] {app_entry['label']}: Framework '{app_fw_name}' ({app_fw_ref}) not installed.")
                    continue

                print(f"\n---> Provisioning {app_entry['label']} (Framework: {matching_fw.get_name()})...")
                try:
                    res = manager.create_example_application(app_entry["id"], framework_ref_or_name=app_fw_ref)
                    print(f"     [OK] Perimeter: {res.get('perimeter_id')}")
                    print(f"     [OK] Compliance Assessment: {res.get('compliance_assessment_name')}")
                    print(f"     [OK] Answers Imported: {res.get('answers_updated')}")
                    print(f"     [OK] Risk Scenarios: {res.get('scenarios_created')}")
                    print(f"     [OK] Controls Linked: {res.get('existing_controls_linked', 0)} active, {res.get('planned_controls_linked', 0)} planned")
                    print(f"     [OK] Findings: {res.get('findings_count', 0)}")
                    results.append({"app": app_entry["name"], "status": "success", "data": res})
                except Exception as e:
                    print(f"     [FAILED] Error creating {app_entry['name']}: {e}")
                    results.append({"app": app_entry["name"], "status": "failed", "error": str(e)})

            print("\n[SUCCESS] Completed provisioning of example applications.")
            return {"results": results, "count": len(results)}

        task_id = TASK_MANAGER.create_task("Provision All Example Applications", _job)
        return jsonify({"task_id": task_id, "message": "Provisioning started."})

    @app.route("/api/provision/app", methods=["POST"])
    def api_provision_app():
        """Provision a single example application."""
        payload = request.get_json() or {}
        app_id = payload.get("app_id") or payload.get("name")
        target_fw = payload.get("framework")

        if not app_id:
            return jsonify({"error": "Missing 'app_id' in request."}), 400

        app_spec = manager.find_example_application(app_id)
        if not app_spec:
            return jsonify({"error": f"Application '{app_id}' not found in catalog."}), 404

        fw_ref = target_fw or app_spec.get("framework_ref")

        def _job():
            matching_fw = manager.find_target_framework(fw_ref)
            fw_display = matching_fw.get_name() if matching_fw and hasattr(matching_fw, "get_name") else (str(matching_fw) if matching_fw else "Default")
            print(f"---> Provisioning {app_spec['label']} in CISO Assistant (Framework: {fw_display})...")
            res = manager.create_example_application(app_spec["id"], framework_ref_or_name=fw_ref)
            print(f"     [OK] Representative User: {res.get('user_email')}")
            print(f"     [OK] Perimeter: {res.get('perimeter_id')}")
            print(f"     [OK] Answers: {res.get('answers_updated')}")
            print(f"     [OK] Scenarios: {res.get('scenarios_created')}")
            print(f"     [OK] Controls: {res.get('existing_controls_linked', 0)} active, {res.get('planned_controls_linked', 0)} planned")
            print(f"     [OK] Findings: {res.get('findings_count', 0)}")
            return res

        task_id = TASK_MANAGER.create_task(f"Provision {app_spec['name']}", _job)
        return jsonify({"task_id": task_id, "message": f"Provisioning {app_spec['name']} started."})

    # -----------------------------------------------------------------------
    # Interactive Audit Demo Intake Endpoint (Feature 4)
    # -----------------------------------------------------------------------

    @app.route("/api/audit-demo", methods=["POST"])
    def api_audit_demo():
        """Create an unanswered application audit demo assigned to a user."""
        payload = request.get_json() or {}
        app_name = payload.get("app_name", "App-Audit-Demo").strip()
        user_email = payload.get("user_email", "").strip()
        first_name = payload.get("first_name", "").strip()
        last_name = payload.get("last_name", "").strip()
        is_third_party = bool(payload.get("is_third_party", True))
        framework = payload.get("framework", "mls").strip()

        if not user_email or "@" not in user_email:
            return jsonify({"error": "A valid 'user_email' is required."}), 400

        def _job():
            print(f"---> Provisioning application '{app_name}' and assigning audit to '{user_email}'...")
            res = manager.create_application_for_audit(
                app_name=app_name,
                user_email=user_email,
                first_name=first_name,
                last_name=last_name,
                is_third_party=is_third_party,
                framework_ref_or_name=framework,
            )
            print(f"     [OK] Application: {res.get('app_name')}")
            print(f"     [OK] Assigned User: {res.get('user_email')} (User Created: {res.get('user_created')})")
            print(f"     [OK] Perimeter: {res.get('perimeter_id')}")
            print(f"     [OK] Assessment: {res.get('compliance_assessment_name')}")
            print(f"     [OK] Assignment: {res.get('assignment_id')}")
            print("Questionnaire is in initial UNANSWERED (0%) state ready for respondent input.")
            return res

        task_id = TASK_MANAGER.create_task(f"Create Audit Demo '{app_name}'", _job)
        return jsonify({"task_id": task_id, "message": "Audit demo creation started."})

    # -----------------------------------------------------------------------
    # Dynamic Risk & Controls Generator Endpoint (Feature 5)
    # -----------------------------------------------------------------------

    @app.route("/api/generate-risks", methods=["POST"])
    def api_generate_risks():
        """Generate Applied Controls and Risk Scenarios for an application."""
        payload = request.get_json() or {}
        app_name = payload.get("app_name", "").strip()
        answers_source = payload.get("answers_source", "live")  # live, profile, custom
        profile_id = payload.get("profile_id")
        custom_yaml_path = payload.get("custom_yaml_path")
        custom_yaml_content = payload.get("custom_yaml_content")

        if not app_name:
            return jsonify({"error": "Missing 'app_name' parameter."}), 400

        # Determine answers YAML file path if applicable
        resolved_yaml = None
        if answers_source == "profile" and profile_id:
            ex_app = manager.find_example_application(profile_id)
            if ex_app and ex_app.get("yaml_path"):
                resolved_yaml = ex_app["yaml_path"]
        elif answers_source == "custom":
            if custom_yaml_content:
                scratch_dir = Path("test_data")
                scratch_dir.mkdir(parents=True, exist_ok=True)
                temp_file = scratch_dir / f"custom_{int(time.time())}_{uuid.uuid4().hex[:6]}.yml"
                with open(temp_file, "w", encoding="utf-8") as f:
                    f.write(custom_yaml_content)
                resolved_yaml = str(temp_file)
            elif custom_yaml_path and Path(custom_yaml_path).exists():
                resolved_yaml = custom_yaml_path

        def _job():
            print(f"---> Generating controls and risk scenarios for '{app_name}'...")
            if resolved_yaml:
                print(f"     Source Answers: {resolved_yaml}")
            else:
                print("     Source Answers: Live answers submitted in CISO Assistant UI")

            res = manager.generate_controls_and_risks_for_application(
                app_name,
                yaml_path=resolved_yaml,
            )
            print(f"     [OK] Applied Controls Created: {res.get('applied_controls_count', 0)}")
            print(f"     [OK] Risk Scenarios Created:   {res.get('scenarios_created', 0)}")
            print(f"     [OK] Controls Linked:          {res.get('existing_controls_linked', 0)} active, {res.get('planned_controls_linked', 0)} planned")
            print(f"     [OK] Audit Findings Generated: {res.get('findings_count', 0)}")
            return res

        task_id = TASK_MANAGER.create_task(f"Generate Risks & Controls for {app_name}", _job)
        return jsonify({"task_id": task_id, "message": "Risk and control generation started."})

    # -----------------------------------------------------------------------
    # Controls Linking Endpoint (Feature 6)
    # -----------------------------------------------------------------------

    @app.route("/api/link-controls", methods=["POST"])
    def api_link_controls():
        """Link active and planned controls to risk scenarios."""
        payload = request.get_json() or {}
        target = payload.get("target", "all").strip()

        def _job():
            if target == "all":
                print("Linking controls across all example applications...")
                res = manager.link_all_controls_to_risk_scenarios()
                for r in res:
                    print(f"  * {r.get('app_name')}: {r.get('scenarios_updated', 0)} scenarios updated | {r.get('existing_controls', 0)} active, {r.get('planned_controls', 0)} planned")
                return {"summary": res}
            else:
                print(f"Linking controls for '{target}'...")
                res = manager.link_controls_for_application(target)
                print(f"  * Updated {res.get('scenarios_updated', 0)} scenarios | {res.get('existing_controls', 0)} active, {res.get('planned_controls', 0)} planned")
                return res

        task_id = TASK_MANAGER.create_task(f"Link Controls ({target})", _job)
        return jsonify({"task_id": task_id, "message": "Control linking started."})

    # -----------------------------------------------------------------------
    # Removal & Teardown Endpoints (Features 6 & 7)
    # -----------------------------------------------------------------------

    @app.route("/api/remove", methods=["POST"])
    def api_remove():
        """Remove example applications from CISO Assistant."""
        payload = request.get_json() or {}
        target = payload.get("target", "all").strip()

        def _job():
            if target == "all":
                status_list = manager.get_status()
                created = [s for s in status_list if s.get("exists")]
                print(f"Removing {len(created)} example applications from CISO Assistant...")
                results = []
                for s in created:
                    app_name = s["name"]
                    print(f"---> Deleting {app_name}...")
                    del_res = manager.remove_example_application(s["id"])
                    results.append({"name": app_name, "details": del_res})
                print("\n[SUCCESS] Completed removal of all example applications.")
                return {"deleted_apps": results, "count": len(results)}
            else:
                print(f"---> Removing {target} from CISO Assistant...")
                del_res = manager.remove_example_application(target)
                print(f"[SUCCESS] Successfully removed {target}.")
                return {"target": target, "details": del_res}

        task_id = TASK_MANAGER.create_task(f"Remove Application(s) ({target})", _job)
        return jsonify({"task_id": task_id, "message": "Removal started."})

    # -----------------------------------------------------------------------
    # Offline Risk Simulation Studio (Feature 8)
    # -----------------------------------------------------------------------

    @app.route("/api/offline-simulation")
    def api_offline_simulation():
        """Run local risk scenario evaluation and matrix calculations without live API calls."""
        app_filter = request.args.get("app_id")
        simulators: dict[str, ApplicationRiskSimulator] = {}
        risk_labels = {0: "1 - Very Low", 1: "2 - Low", 2: "3 - Medium", 3: "4 - High", 4: "5 - Very High"}
        priority_labels = {1: "1 (Urgent)", 2: "2 (High)", 3: "3 (Medium)", 4: "4 (Low)"}

        # Initialize 4x4 matrix stats counts
        matrix_grid = {f"{lh}_{imp}": 0 for lh in range(1, 5) for imp in range(1, 5)}

        evaluations = []
        apps = manager.get_example_applications()
        if app_filter:
            apps = [a for a in apps if a.get("id") == app_filter or a.get("name") == app_filter]

        for app_entry in apps:
            answers_path = app_entry.get("yaml_path")
            if not answers_path or not Path(answers_path).exists():
                continue

            fw_yaml = app_entry.get("framework_yaml", "YML/newDPP.yml")
            if fw_yaml not in simulators:
                simulators[fw_yaml] = ApplicationRiskSimulator(fw_yaml)
            sim = simulators[fw_yaml]

            results = sim.evaluate_application(answers_path)
            conf_impact = results.get("confidentiality_impact", results.get("impact_level", 1))
            avail_impact = results.get("availability_impact", conf_impact)

            # Filter scores to requirement nodes
            scores = {
                req: score for req, score in sorted(results["requirement_scores"].items())
                if req in sim.req_nodes
            }

            scenarios_list = []
            for sc_name, sc_data in results["scenarios"].items():
                lh = sc_data["scaled_likelihood"]
                imp = sc_data["scaled_impact"]
                key = f"{lh}_{imp}"
                if key in matrix_grid:
                    matrix_grid[key] += 1

                m_id = sc_data["matrix_risk_id"]
                p_id = sc_data["control_priority"]
                scenarios_list.append({
                    "name": sc_name,
                    "likelihood": lh,
                    "impact": imp,
                    "matrix_risk_id": m_id,
                    "matrix_risk_label": risk_labels.get(m_id, str(m_id)),
                    "control_priority": p_id,
                    "priority_label": priority_labels.get(p_id, str(p_id)),
                })

            evaluations.append({
                "id": app_entry.get("id"),
                "name": app_entry.get("name"),
                "label": app_entry.get("label"),
                "description": app_entry.get("description"),
                "framework_name": app_entry.get("framework_name", "Multi-level DPP"),
                "framework_ref": app_entry.get("framework_ref", "mls"),
                "confidentiality_impact": conf_impact,
                "availability_impact": avail_impact,
                "requirement_scores": scores,
                "scenarios": scenarios_list,
            })

        return jsonify({
            "applications": evaluations,
            "matrix_counts": matrix_grid,
        })

    # -----------------------------------------------------------------------
    # Disaster Recovery & Backup Endpoints (Feature 9)
    # -----------------------------------------------------------------------

    @app.route("/api/backups")
    def api_backups():
        """List all discovered backups with metadata and hashes."""
        backups = manager.list_backups()
        return jsonify(backups)

    @app.route("/api/backups/create", methods=["POST"])
    def api_backup_create():
        """Create a new backup (workspace snapshot or database dump)."""
        payload = request.get_json() or {}
        b_type = payload.get("type", "snapshot").lower()

        def _job():
            if b_type == "dump":
                print("Initiating full server-side database dump via /api/serdes/dump-db/...")
                dump_path = manager.create_database_dump()
                if not dump_path:
                    raise RuntimeError("Failed to create database dump.")
                stat = manager.inspect_backup(dump_path)
                print(f"[SUCCESS] Database dump created: {stat['filename']} ({stat['size_formatted']})")
                print(f"SHA-256: {stat['sha256']}")
                return stat
            else:
                print("Exporting workspace resources to portable JSON snapshot...")
                snapshot_path = manager.create_workspace_snapshot()
                stat = manager.inspect_backup(snapshot_path)
                print(f"[SUCCESS] Workspace snapshot created: {stat['filename']} ({stat['size_formatted']})")
                print(f"SHA-256: {stat['sha256']}")
                return stat

        task_id = TASK_MANAGER.create_task(f"Create {b_type.capitalize()} Backup", _job)
        return jsonify({"task_id": task_id, "message": f"Backup creation ({b_type}) started."})

    @app.route("/api/backups/inspect/<filename>")
    def api_backup_inspect(filename: str):
        """Inspect a specific backup file."""
        safe_name = secure_filename(filename)
        b_dir = manager.backup_manager.get_backup_dir()
        target = b_dir / safe_name
        if not target.exists():
            abort(404, description=f"Backup file '{safe_name}' not found.")
        stat = manager.inspect_backup(target)
        return jsonify(stat)

    @app.route("/api/backups/download/<filename>")
    def api_backup_download(filename: str):
        """Download a backup file."""
        safe_name = secure_filename(filename)
        b_dir = manager.backup_manager.get_backup_dir()
        if not (b_dir / safe_name).exists():
            abort(404, description=f"Backup file '{safe_name}' not found.")
        return send_from_directory(str(b_dir.resolve()), safe_name, as_attachment=True)

    @app.route("/api/backups/upload", methods=["POST"])
    def api_backup_upload():
        """Upload a backup file (.json, .dump, .sql) to the backups directory."""
        if "file" not in request.files:
            return jsonify({"error": "No file part in the request."}), 400

        file = request.files["file"]
        if not file or not file.filename:
            return jsonify({"error": "No file selected."}), 400

        safe_name = secure_filename(file.filename)
        if not any(safe_name.endswith(ext) for ext in (".json", ".dump", ".sql")):
            return jsonify({"error": "Invalid backup file extension. Must be .json, .dump, or .sql."}), 400

        b_dir = manager.backup_manager.get_backup_dir()
        target_path = b_dir / safe_name
        file.save(target_path)

        stat = manager.inspect_backup(target_path)
        return jsonify({
            "message": f"Successfully uploaded '{safe_name}'.",
            "stat": stat,
        })

    @app.route("/api/backups/restore", methods=["POST"])
    def api_backup_restore():
        """Restore workspace state from a backup file."""
        payload = request.get_json() or {}
        filename = payload.get("filename", "").strip()
        safe_name = secure_filename(filename)
        b_dir = manager.backup_manager.get_backup_dir()
        target = b_dir / safe_name

        if not target.exists():
            return jsonify({"error": f"Backup file '{safe_name}' not found."}), 404

        stat = manager.inspect_backup(target)
        b_type = stat.get("type", "unknown")

        def _job():
            print(f"---> Restoring from {safe_name} (Type: {b_type}, Size: {stat['size_formatted']})...")
            print(f"     SHA-256: {stat['sha256']}")
            if b_type == "database_dump" or target.suffix in (".dump", ".sql"):
                res = manager.restore_database_dump(target)
                if res is True or (isinstance(res, dict) and not res.get("error")):
                    print("[SUCCESS] Database restore completed successfully!")
                    return {"status": "success", "type": "dump"}
                else:
                    raise RuntimeError(f"Database restore failed: {res}")
            elif b_type == "workspace_snapshot":
                res = manager.restore_workspace_snapshot(target)
                if res.get("status") == "success":
                    print("[SUCCESS] Workspace snapshot restored successfully!")
                    return res
                else:
                    raise RuntimeError(f"Snapshot restore failed: {res.get('details')}")
            else:
                raise ValueError(f"Unrecognized backup format: {safe_name}")

        task_id = TASK_MANAGER.create_task(f"Restore Backup ({safe_name})", _job)
        return jsonify({"task_id": task_id, "message": "Restore operation started."})

    @app.route("/api/backups/<filename>", methods=["DELETE"])
    def api_backup_delete(filename: str):
        """Safely delete a backup file."""
        safe_name = secure_filename(filename)
        b_dir = manager.backup_manager.get_backup_dir()
        target = b_dir / safe_name
        if not target.exists():
            abort(404, description=f"Backup file '{safe_name}' not found.")
        try:
            target.unlink()
            return jsonify({"message": f"Backup '{safe_name}' deleted successfully."})
        except Exception as e:
            return jsonify({"error": f"Failed to delete backup: {e}"}), 500

    # -----------------------------------------------------------------------
    # Legacy Pipeline & Model Importer Endpoints
    # -----------------------------------------------------------------------

    @app.route("/api/pipeline", methods=["POST"])
    def api_run_pipeline():
        """Run the full legacy orchestration pipeline."""
        def _job():
            print("Running full legacy CISO Assistant orchestration pipeline...")
            data = utils.initialize_data_objects()
            initial_counts = utils.capture_counts(data)

            data["asset_dict"].create_missing_assets(data["perimeter_dict"])
            data["asset_dict"].reload()

            data["compliance_assessment_dict"].create_missing_compliance_assessments(
                data["framework_dict"],
                data["perimeter_dict"],
                data["asset_dict"],
            )

            data["compliance_assessment_dict"].assign_requirements_to_perimeter_owner(
                data["perimeter_dict"],
                data["compliance_assessment_dict"],
                data["requirement_assessment_dict"],
                data["requirement_assignment_dict"],
            )

            data["entity_assessment_dict"].create_external_entity_audits(
                data["entity_dict"],
                data["framework_dict"],
            )

            data["compliance_assessment_dict"].create_risk_assessments(
                data["risk_assessment_dict"],
                data["risk_scenario_dict"],
                data["applied_control_dict"],
                data["asset_dict"],
                data["library_file"],
                data["requirement_assessment_dict"],
                data["risk_matrix_dict"],
                data["framework_dict"],
            )

            data["compliance_assessment_dict"].create_missing_applied_controls(
                data["applied_control_dict"],
                data["perimeter_dict"],
                data["reference_control_dict"],
            )

            data["compliance_assessment_dict"].update_asset_criticality(
                criticality_mapping,
                data["asset_dict"],
            )

            data["compliance_assessment_dict"].create_findings_assessments(
                data["findings_assessment_dict"],
                data["finding_dict"],
                requirement_assessment_dict=data["requirement_assessment_dict"],
                asset_dict=data["asset_dict"],
                vulnerability_dict=data.get("vulnerability_dict"),
                threat_dict=data.get("threat_dict"),
                framework_file=data.get("library_file"),
            )

            final_counts = utils.capture_counts(data)
            utils.print_run_summary(initial_counts, final_counts)
            return {
                "initial_counts": initial_counts,
                "final_counts": final_counts,
            }

        task_id = TASK_MANAGER.create_task("Run Full Orchestration Pipeline", _job)
        return jsonify({"task_id": task_id, "message": "Pipeline execution started."})

    @app.route("/api/model-import", methods=["POST"])
    def api_model_import():
        """Import department/entity YAML model into domains and external entities."""
        payload = request.get_json() or {}
        yaml_path = payload.get("yaml_path", "YML/sample_entity_assessment_model.yml")
        create_assessments = bool(payload.get("create_assessments", False))

        if not Path(yaml_path).exists():
            return jsonify({"error": f"YAML model file '{yaml_path}' not found."}), 404

        def _job():
            print(f"---> Importing department & TPRM model from {yaml_path}...")
            summary = import_department_external_entity_model(
                yaml_path=yaml_path,
                create_entity_assessments=create_assessments,
            )
            print(f"     Domains processed: {summary['domains_processed']}")
            print(f"     Entities processed: {summary['entities_processed']}")
            print(f"     Representative links: {summary['representative_links_created']}")
            print(f"     Assessments created: {summary['entity_assessments_created']}")
            if summary.get("issues"):
                print(f"     [WARNING] Issues encountered: {len(summary['issues'])}")
            return summary

        task_id = TASK_MANAGER.create_task(f"Import TPRM Model ({Path(yaml_path).name})", _job)
        return jsonify({"task_id": task_id, "message": "Model import started."})

    return app


if __name__ == "__main__":
    flask_app = create_app()
    flask_app.run(host="127.0.0.1", port=5000, debug=True)

