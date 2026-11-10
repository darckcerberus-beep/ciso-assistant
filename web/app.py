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
import queue
import sys
import threading
import time
from typing import Any
from collections.abc import Callable
import uuid

try:
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
    HAS_FLASK = True
except ImportError:
    Flask = None  # type: ignore
    Response = None  # type: ignore
    abort = None  # type: ignore
    jsonify = None  # type: ignore
    render_template = None  # type: ignore
    request = None  # type: ignore
    send_from_directory = None  # type: ignore
    secure_filename = None  # type: ignore
    HAS_FLASK = False

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
    """Manages asynchronous tasks with a sequential FIFO queue, real-time log capturing, and event notifications."""

    def __init__(self, max_history: int = 50, max_workers: int = 1):
        self.max_history = max_history
        self.max_workers = max_workers
        self.tasks: dict[str, dict[str, Any]] = {}
        self.events: dict[str, threading.Event] = {}
        self._lock = threading.RLock()
        self._queue: queue.Queue = queue.Queue()
        self._current_task_id: str | None = None
        self._workers: list[threading.Thread] = []
        self._stop_event = threading.Event()
        self._ensure_workers()

    def _ensure_workers(self) -> None:
        """Ensure background worker threads are alive and running."""
        with self._lock:
            if self._stop_event.is_set():
                return
            self._workers = [w for w in self._workers if w.is_alive()]
            while len(self._workers) < self.max_workers:
                worker = threading.Thread(target=self._worker_loop, daemon=True)
                worker.start()
                self._workers.append(worker)

    def _worker_loop(self) -> None:
        """Continuously pull tasks from the FIFO queue and execute them sequentially."""
        while not self._stop_event.is_set():
            try:
                item = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue

            if item is None:
                self._queue.task_done()
                break

            task_id, func, args, kwargs = item
            try:
                self._run_task(task_id, func, *args, **kwargs)
            finally:
                self._queue.task_done()

    def create_task(self, name: str, func: Callable[..., Any], *args: Any, **kwargs: Any) -> str:
        """Create, enqueue, and launch a background task via the sequential FIFO queue."""
        self._ensure_workers()
        task_id = f"task_{int(time.time())}_{uuid.uuid4().hex[:6]}"
        now_iso = datetime.now(timezone.utc).isoformat()
        task_info = {
            "id": task_id,
            "name": name,
            "status": "queued",  # queued, running, completed, failed, cancelled
            "queued_at": now_iso,
            "started_at": None,
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
                if oldest_id != task_id and self.tasks[oldest_id]["status"] in ("completed", "failed", "cancelled"):
                    del self.tasks[oldest_id]

            active = self._current_task_id is not None
            pos = len(self._queue.queue) + (1 if active else 0)

        if pos > 0:
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
            task_info["logs"].append(
                f"[{ts}] === Task enqueued in position #{pos}. Waiting for previous operations to complete... ==="
            )

        self._queue.put((task_id, func, args, kwargs))
        return task_id

    def _run_task(self, task_id: str, func: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        """Execute a task pulled from the FIFO queue."""
        with self._lock:
            task_info = self.tasks.get(task_id)
            if not task_info or task_info.get("status") == "cancelled":
                return
            task_info["status"] = "running"
            task_info["started_at"] = datetime.now(timezone.utc).isoformat()
            self._current_task_id = task_id
            name = task_info["name"]

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
            with self._lock:
                if self._current_task_id == task_id:
                    self._current_task_id = None

    def _get_queue_position_unlocked(self, task_id: str) -> int | None:
        """Internal helper to calculate queue position when self._lock is already held."""
        if self._current_task_id == task_id:
            return 0
        for idx, item in enumerate(list(self._queue.queue), start=1):
            if item[0] == task_id:
                return idx
        return None

    def get_queue_position(self, task_id: str) -> int | None:
        """Return 1-based queue position if waiting in queue, 0 if currently running, or None if done/not found."""
        with self._lock:
            return self._get_queue_position_unlocked(task_id)

    def get_queue_status(self) -> dict[str, Any]:
        """Return a snapshot of current queue state."""
        with self._lock:
            queued_items = list(self._queue.queue)
            active_info = None
            if self._current_task_id and self._current_task_id in self.tasks:
                t = self.tasks[self._current_task_id]
                active_info = {
                    "id": t["id"],
                    "name": t["name"],
                    "status": t["status"],
                    "started_at": t.get("started_at"),
                }
            queued_list = []
            for idx, item in enumerate(queued_items, start=1):
                tid = item[0]
                t = self.tasks.get(tid)
                if t:
                    queued_list.append({
                        "id": t["id"],
                        "name": t["name"],
                        "status": t["status"],
                        "queued_at": t.get("queued_at"),
                        "position": idx,
                    })
            return {
                "active_task": active_info,
                "queue_length": len(queued_list),
                "queued_tasks": queued_list,
                "max_workers": self.max_workers,
            }

    def clear_queue(self) -> int:
        """Clear all waiting tasks from the queue."""
        with self._lock:
            cleared_count = 0
            while not self._queue.empty():
                try:
                    item = self._queue.get_nowait()
                    task_id = item[0]
                    if task_id in self.tasks and self.tasks[task_id]["status"] == "queued":
                        self.tasks[task_id]["status"] = "cancelled"
                        self.tasks[task_id]["finished_at"] = datetime.now(timezone.utc).isoformat()
                        self.tasks[task_id]["logs"].append("[CANCELLED] Task cancelled while waiting in queue.")
                    cleared_count += 1
                except (queue.Empty, IndexError):
                    break
            return cleared_count

    def stop(self, timeout: float = 2.0) -> None:
        """Stop background worker threads."""
        self._stop_event.set()
        with self._lock:
            for _ in range(self.max_workers):
                self._queue.put(None)
            for w in self._workers:
                w.join(timeout=timeout)
            self._workers.clear()

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
                "queued_at": info.get("queued_at"),
                "started_at": info["started_at"],
                "finished_at": info["finished_at"],
                "logs": list(info["logs"]),
                "result": info["result"],
                "error": info["error"],
                "queue_position": self._get_queue_position_unlocked(task_id),
            }

    def list_tasks(self) -> list[dict[str, Any]]:
        """List summary of all tracked tasks."""
        with self._lock:
            return [
                {
                    "id": t["id"],
                    "name": t["name"],
                    "status": t["status"],
                    "queued_at": t.get("queued_at"),
                    "started_at": t["started_at"],
                    "finished_at": t["finished_at"],
                    "error": t["error"],
                    "log_count": len(t["logs"]),
                    "queue_position": self._get_queue_position_unlocked(t["id"]),
                }
                for t in reversed(list(self.tasks.values()))
            ]


TASK_MANAGER = BackgroundTaskManager()


# ---------------------------------------------------------------------------
# App Factory & Routes
# ---------------------------------------------------------------------------

def create_app(test_config: dict[str, Any] | None = None, manager: ExamplesManager | None = None) -> Any:
    """Create and configure the Flask Web Application."""
    if not HAS_FLASK:
        raise RuntimeError("Flask and Werkzeug are required to run the web application.")
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).resolve().parent / "templates"),
        static_folder=str(Path(__file__).resolve().parent / "static"),
    )
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.jinja_env.auto_reload = True

    if test_config:
        app.config.update(test_config)

    if manager is None:
        manager = app.config.get("manager") or ExamplesManager()
    app.manager = manager

    @app.after_request
    def add_cache_headers(response):
        """Prevent browser caching so UI updates and background themes reflect immediately."""
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    # -----------------------------------------------------------------------
    # Web UI Page
    # -----------------------------------------------------------------------

    @app.route("/")
    def index():
        """Render main Web UI dashboard."""
        return render_template(
            "index.html",
            base_url=utils.BASE_URL,
            target_folder=getattr(manager, "folder_name", None) or EXAMPLE_FOLDER_NAME,
        )

    # -----------------------------------------------------------------------
    # Status & Inventory Endpoints
    # -----------------------------------------------------------------------

    @app.route("/api/status")
    def api_status():
        """Retrieve deployment status across all applications."""
        target_folder = getattr(manager, "folder_name", None) or EXAMPLE_FOLDER_NAME
        wait_sec = float(request.args.get("wait", 0.0))

        connected, conn_msg = manager.test_connection()
        if not connected:
            return jsonify({
                "connected": False,
                "message": conn_msg,
                "base_url": utils.BASE_URL,
                "folder_name": target_folder,
                "applications": [],
                "installed_frameworks": [],
                "available_frameworks": manager.get_available_frameworks(installed_only=False),
                "catalog_frameworks": FRAMEWORK_CATALOG,
                "catalog": manager.get_example_applications(),
                "domains": [],
                "summary": {
                    "total_catalog": len(manager.get_example_applications()),
                    "total_domains": 0,
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

        # Query all organizational domains in CISO Assistant
        domains_list = []
        try:
            raw_domains = manager.get_domains()
            domains_list = [
                {
                    "id": d.get_id(),
                    "name": d.get_name(),
                    "description": getattr(d, "get_description", lambda: "")(),
                    "parent_folder": getattr(d, "get_parent_folder", lambda: None)(),
                }
                for d in raw_domains
            ]
        except Exception as e:
            LOGGER.warning(f"Error querying domains: {e}")

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
            "folder_name": target_folder,
            "applications": status_list,
            "installed_frameworks": installed_fws,
            "available_frameworks": manager.get_available_frameworks(installed_only=False),
            "catalog_frameworks": FRAMEWORK_CATALOG,
            "catalog": catalog_apps,
            "domains": domains_list,
            "summary": {
                "total_catalog": len(catalog_apps),
                "total_domains": len(domains_list),
                "deployed": len(deployed_apps),
                "completed_audits": completed_audits,
                "partial_audits": partial_audits,
                "total_risks": total_risks,
                "total_controls": total_controls,
                "total_findings": total_findings,
            },
        })

    @app.route("/api/domains", methods=["GET", "POST"])
    def api_domains():
        """Retrieve or create organizational domains/folders in CISO Assistant."""
        if request.method == "POST":
            payload = request.get_json() or {}
            name = payload.get("name", "").strip()
            description = payload.get("description", "").strip() or None
            parent_domain = payload.get("parent_domain", "").strip() or None

            if not name:
                return jsonify({"error": "Domain name is required."}), 400

            def _create_job():
                print(f"---> Creating organizational domain '{name}' in CISO Assistant...")
                res = manager.create_domain(
                    name=name,
                    description=description,
                    parent_folder_id=parent_domain,
                    create_iam_groups=True,
                )
                if isinstance(res, dict) and res.get("error"):
                    raise RuntimeError(res.get("details") or res.get("error"))
                dom_id = res.get("id") if isinstance(res, dict) else (res.get_id() if hasattr(res, "get_id") else str(res))
                print(f"     [OK] Domain Created: {name} (ID: {dom_id})")
                return res

            task_id = TASK_MANAGER.create_task(f"Create Domain '{name}'", _create_job)
            return jsonify({"task_id": task_id, "message": f"Creation of domain '{name}' started."})

        # GET: List all domains
        connected, _ = manager.test_connection()
        if not connected:
            return jsonify({"domains": [], "connected": False})

        domains = manager.get_domains()
        return jsonify({
            "connected": True,
            "domains": [
                {
                    "id": d.get_id(),
                    "name": d.get_name(),
                    "description": getattr(d, "get_description", lambda: "")(),
                    "parent_folder": getattr(d, "get_parent_folder", lambda: None)(),
                }
                for d in domains
            ],
        })

    @app.route("/api/frameworks")
    def api_frameworks():
        """Retrieve installed and catalog frameworks."""
        installed = manager.get_installed_frameworks()
        available = manager.get_available_frameworks(installed_only=False)
        return jsonify({
            "installed": installed,
            "catalog": FRAMEWORK_CATALOG,
            "available": available,
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
            "queued_at": info.get("queued_at"),
            "started_at": info["started_at"],
            "finished_at": info["finished_at"],
            "logs": logs_slice,
            "total_logs": len(info["logs"]),
            "result": info["result"],
            "error": info["error"],
            "queue_position": info.get("queue_position"),
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
                    q_pos = TASK_MANAGER.get_queue_position(task_id)

                while sent_idx < len(logs):
                    line = logs[sent_idx]
                    yield f"data: {json.dumps({'line': line, 'index': sent_idx, 'status': status, 'queue_position': q_pos})}\n\n"
                    sent_idx += 1

                if status in ("completed", "failed", "cancelled"):
                    yield f"data: {json.dumps({'done': True, 'status': status, 'result': result, 'error': error})}\n\n"
                    break

                if not logs:
                    yield f"data: {json.dumps({'status': status, 'queue_position': q_pos})}\n\n"

                time.sleep(0.2)

        return Response(event_generator(), mimetype="text/event-stream")

    @app.route("/api/queue")
    def api_queue():
        """Retrieve current background task queue status and pending items."""
        return jsonify(TASK_MANAGER.get_queue_status())

    @app.route("/api/queue/clear", methods=["POST"])
    def api_queue_clear():
        """Clear all pending tasks from the queue."""
        cleared = TASK_MANAGER.clear_queue()
        return jsonify({"cleared": cleared, "message": f"Cleared {cleared} pending task(s) from queue."})

    # -----------------------------------------------------------------------
    # Provisioning Endpoints
    # -----------------------------------------------------------------------

    @app.route("/api/provision/all", methods=["POST"])
    def api_provision_all():
        """Provision all 12 example applications in CISO Assistant."""
        payload = request.get_json() or {}
        target_domain = payload.get("domain")

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
                    res = manager.create_example_application(
                        app_entry["id"],
                        framework_ref_or_name=app_fw_ref,
                        domain_name=target_domain,
                    )
                    print(f"     [OK] Domain: {res.get('domain_name')}")
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
        target_domain = payload.get("domain")

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
            res = manager.create_example_application(
                app_spec["id"],
                framework_ref_or_name=fw_ref,
                domain_name=target_domain,
            )
            print(f"     [OK] Domain: {res.get('domain_name')}")
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
        framework = payload.get("framework", "").strip()
        target_domain = payload.get("domain")

        if not user_email or "@" not in user_email:
            return jsonify({"error": "A valid 'user_email' is required."}), 400

        # Check installed frameworks before initiating audit task
        installed_fws = manager.get_installed_frameworks()
        if not installed_fws:
            return jsonify({
                "error": "No compliance frameworks are currently installed in CISO Assistant. Cannot create audit demonstration. Please import or load a framework first."
            }), 400

        # Resolve target framework: if specified, verify it is installed; if not, use default or first installed
        if framework:
            matching_fw = manager.find_target_framework(framework)
            if not matching_fw:
                installed_names = ", ".join(f"'{f.get('name')}' ({f.get('ref_id')})" for f in installed_fws)
                return jsonify({
                    "error": f"Framework '{framework}' is not installed in CISO Assistant. Available installed frameworks: {installed_names}"
                }), 400
            target_fw_ref = framework
        else:
            default_fw = manager.find_target_framework(None)
            if default_fw:
                target_fw_ref = (
                    getattr(default_fw, "json_object", {}).get("ref_id")
                    or default_fw.get_name()
                )
            else:
                target_fw_ref = installed_fws[0].get("ref_id") or installed_fws[0].get("name")

        implementation_groups = payload.get("implementation_groups")
        if implementation_groups is not None and not isinstance(implementation_groups, list):
            implementation_groups = [str(implementation_groups)]

        def _job():
            print(f"---> Provisioning application '{app_name}' and assigning audit to '{user_email}' (Framework: {target_fw_ref})...")
            res = manager.create_application_for_audit(
                app_name=app_name,
                user_email=user_email,
                first_name=first_name,
                last_name=last_name,
                is_third_party=is_third_party,
                framework_ref_or_name=target_fw_ref,
                domain_name=target_domain,
                implementation_groups=implementation_groups,
            )
            print(f"     [OK] Application: {res.get('app_name')}")
            print(f"     [OK] Domain: {res.get('domain_name')}")
            print(f"     [OK] Assigned User: {res.get('user_email')} (User Created: {res.get('user_created')})")
            print(f"     [OK] Perimeter: {res.get('perimeter_id')}")
            print(f"     [OK] Assessment: {res.get('compliance_assessment_name')}")
            print(f"     [OK] Assignment: {res.get('assignment_id')}")
            if res.get("selected_implementation_groups"):
                print(f"     [OK] Implementation Groups: {res.get('selected_implementation_groups')}")
            print("Questionnaire is in initial UNANSWERED (0%) state ready for respondent input.")
            return res

        task_id = TASK_MANAGER.create_task(f"Create Audit Demo '{app_name}'", _job)
        return jsonify({"task_id": task_id, "message": "Audit demo creation started."})

    @app.route("/api/frameworks/<path:framework_ref>/implementation-groups")
    def api_framework_implementation_groups(framework_ref: str):
        """Retrieve available implementation groups for a framework."""
        dep_info = manager.determine_implementation_groups_triggered_by_others(framework_ref)
        return jsonify({
            "framework": framework_ref,
            "implementation_groups": dep_info.get("all_groups", []),
            "always_selectable_groups": dep_info.get("always_selectable_groups", []),
            "hidden_groups": dep_info.get("hidden_groups", []),
            "triggered_groups": dep_info.get("triggered_groups", []),
            "visible_groups": dep_info.get("visible_groups", []),
            "dependency_map": dep_info.get("dependency_map", {}),
            "summary": dep_info.get("summary", {}),
        })

    @app.route("/api/audits/<path:app_name>/implementation-groups", methods=["GET", "POST", "PATCH"])
    def api_audit_implementation_groups(app_name: str):
        """Inspect or update implementation groups for an audit."""
        if request.method == "GET":
            try:
                info = manager.get_audit_implementation_groups(app_name)
                return jsonify(info)
            except ValueError as e:
                return jsonify({"error": str(e)}), 404
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        payload = request.get_json() or {}
        groups = payload.get("groups", [])
        mode = payload.get("mode", "add")
        if not isinstance(groups, list):
            return jsonify({"error": "'groups' must be a list of implementation group names or IDs."}), 400

        select_kwargs = {}
        if "sync_existing_assignments" in payload:
            select_kwargs["sync_existing_assignments"] = payload["sync_existing_assignments"]

        try:
            info = manager.select_audit_implementation_groups(
                app_name,
                groups=groups,
                mode=mode,
                **select_kwargs
            )
            return jsonify({
                "message": f"Successfully updated implementation groups for '{app_name}'.",
                "data": info,
            })
        except ValueError as e:
            return jsonify({"error": str(e)}), 404
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/audits/<path:app_name>/assign-implementation-groups", methods=["POST"])
    def api_audit_assign_implementation_groups(app_name: str):
        """Assign triggered or specified implementation groups to a respondent and start the assignment."""
        payload = request.get_json() or {}
        groups = payload.get("groups")
        if groups is not None and not isinstance(groups, list):
            return jsonify({"error": "'groups' must be a list of implementation group names or IDs."}), 400
        user_email = payload.get("user_email") or payload.get("email")
        first_name = payload.get("first_name")
        last_name = payload.get("last_name")
        start = payload.get("start", True)

        try:
            res = manager.assign_audit_implementation_groups(
                app_name,
                groups=groups,
                user_email=user_email,
                first_name=first_name,
                last_name=last_name,
                start=start,
            )
            return jsonify({
                "success": True,
                "message": f"Successfully assigned implementation groups to {res.get('assigned_user')}.",
                "data": res,
            })
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            LOGGER.error(f"Error assigning implementation groups: {e}")
            return jsonify({"error": str(e)}), 500

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
        """Create a new backup (workspace snapshot, framework snapshot, or database dump)."""
        payload = request.get_json() or {}
        b_type = payload.get("type", "snapshot").lower()
        notes = payload.get("notes")
        fw_id = payload.get("framework_id") or payload.get("framework")

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
            elif b_type in ("framework", "framework_snapshot"):
                print("Exporting framework version & questionnaire answers snapshot...")
                snap_path = manager.create_framework_snapshot(framework_id_or_ref=fw_id, notes=notes)
                stat = manager.inspect_backup(snap_path)
                print(f"[SUCCESS] Framework snapshot created: {stat['filename']} ({stat['size_formatted']})")
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
            elif b_type in ("framework_snapshot", "framework_answers_snapshot"):
                dry_run = payload.get("dry_run", False)
                ca_id = payload.get("compliance_assessment_id")
                res = manager.restore_framework_snapshot(target, compliance_assessment_id=ca_id, dry_run=dry_run)
                if res.get("status") == "success":
                    print(f"[SUCCESS] Framework snapshot restored successfully! ({res.get('total_requirements_updated')} updated)")
                    return res
                else:
                    raise RuntimeError(f"Framework snapshot restore failed: {res.get('details')}")
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
            # Check framework_snapshots subdir
            target_fw = b_dir / "framework_snapshots" / safe_name
            if target_fw.exists():
                target = target_fw
            else:
                abort(404, description=f"Backup file '{safe_name}' not found.")
        try:
            target.unlink()
            return jsonify({"message": f"Backup '{safe_name}' deleted successfully."})
        except Exception as e:
            return jsonify({"error": f"Failed to delete backup: {e}"}), 500

    @app.route("/api/framework-snapshots")
    def api_framework_snapshots_list():
        """List all framework version & questionnaire answer snapshots."""
        backups = manager.list_backups()
        fw_snaps = [b for b in backups if b.get("type") == "framework_snapshot"]
        return jsonify(fw_snaps)

    @app.route("/api/framework-snapshots/create", methods=["POST"])
    def api_framework_snapshot_create():
        """Create a framework version & questionnaire answers snapshot."""
        payload = request.get_json() or {}
        fw_id = payload.get("framework_id") or payload.get("framework")
        notes = payload.get("notes")

        def _job():
            print("Creating framework & questionnaire answers snapshot...")
            snap_path = manager.create_framework_snapshot(framework_id_or_ref=fw_id, notes=notes)
            stat = manager.inspect_backup(snap_path)
            print(f"[SUCCESS] Framework snapshot created: {stat['filename']} ({stat['size_formatted']})")
            return stat

        task_id = TASK_MANAGER.create_task("Create Framework Snapshot", _job)
        return jsonify({"task_id": task_id, "message": "Framework snapshot creation started."})

    @app.route("/api/framework-snapshots/restore", methods=["POST"])
    def api_framework_snapshot_restore():
        """Restore or migrate questionnaire answers from a framework snapshot."""
        payload = request.get_json() or {}
        filename = payload.get("filename", "").strip()
        dry_run = payload.get("dry_run", False)
        ca_id = payload.get("compliance_assessment_id")
        remap_rules = payload.get("remap_rules")

        safe_name = secure_filename(filename)
        b_dir = manager.backup_manager.get_backup_dir()
        target = b_dir / safe_name
        if not target.exists():
            target = b_dir / "framework_snapshots" / safe_name

        if not target.exists():
            return jsonify({"error": f"Framework snapshot file '{safe_name}' not found."}), 404

        def _job():
            print(f"Restoring framework answers from {safe_name} (Dry Run: {dry_run})...")
            res = manager.restore_framework_snapshot(
                target,
                compliance_assessment_id=ca_id,
                dry_run=dry_run,
                remap_rules=remap_rules,
            )
            if res.get("status") == "success":
                print(f"[SUCCESS] Framework snapshot restored! ({res.get('total_requirements_updated')} requirements updated)")
                return res
            else:
                raise RuntimeError(f"Framework restore failed: {res.get('details')}")

        task_id = TASK_MANAGER.create_task(f"Restore Framework Snapshot ({safe_name})", _job)
        return jsonify({"task_id": task_id, "message": "Framework restore operation started."})

    @app.route("/api/framework-snapshots/diff", methods=["POST"])
    def api_framework_snapshot_diff():
        """Diff two framework snapshots or compare snapshot against live state."""
        payload = request.get_json() or {}
        snap_a = payload.get("snapshot_a", "").strip()
        snap_b = payload.get("snapshot_b", "live").strip()

        b_dir = manager.backup_manager.get_backup_dir()
        path_a = b_dir / secure_filename(snap_a)
        if not path_a.exists():
            path_a = b_dir / "framework_snapshots" / secure_filename(snap_a)
        if not path_a.exists():
            return jsonify({"error": f"Snapshot A '{snap_a}' not found."}), 404

        path_b = None
        if snap_b and snap_b.lower() != "live":
            path_b = b_dir / secure_filename(snap_b)
            if not path_b.exists():
                path_b = b_dir / "framework_snapshots" / secure_filename(snap_b)
            if not path_b.exists():
                return jsonify({"error": f"Snapshot B '{snap_b}' not found."}), 404

        diff = manager.diff_framework_snapshots(path_a, path_b)
        return jsonify(diff)

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

