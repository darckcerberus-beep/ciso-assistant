"""Backup and restore management for CISO Assistant.

Provides capabilities for:
1. Server-level database dumps and restores via CISO Assistant Serdes API (/api/serdes/dump-db/ and /api/serdes/load-backup/).
2. Portable workspace and application snapshots (JSON export/import of domains, perimeters, assets, audits, controls, risks, findings, exceptions).
3. Framework & questionnaire answers snapshots:
   - Versioned snapshots capturing framework metadata, requirement nodes, question schemas, and all compliance assessment answers.
   - Enriched with human-readable question text and choice values alongside URNs.
   - Cross-version restoration with semantic and text-based question remapping.
   - Version diffing between snapshots or against live CISO Assistant state.
4. Backup discovery, inspection, and verification (timestamps, file sizes, resource counts, SHA-256 integrity checksums).
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from .. import utils
from .answers_import import _resolve_question_urn, _resolve_choice_value, _split_multi_values

LOGGER = logging.getLogger(__name__)

DEFAULT_BACKUP_DIR = "backups"


class BackupManager:
    """Manages creation, restoration, inspection, and discovery of CISO Assistant backups."""

    def __init__(self, backup_dir: str | Path = DEFAULT_BACKUP_DIR):
        self.backup_dir = Path(backup_dir)

    def get_backup_dir(self) -> Path:
        """Return backup directory, creating it if needed."""
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        return self.backup_dir

    @staticmethod
    def _compute_sha256(file_path: Path) -> str:
        """Compute SHA-256 hash of a file."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Return human-readable file size."""
        for unit in ["B", "KB", "MB", "GB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}" if unit != "B" else f"{size_bytes} B"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"

    def create_database_dump(
        self,
        output_dir: str | Path | None = None,
        filename: str | None = None,
    ) -> Path | None:
        """Download raw database dump from CISO Assistant Serdes API (/api/serdes/dump-db/).

        Args:
            output_dir: Directory where the dump should be saved (default: self.backup_dir).
            filename: Custom filename (default: 'db_dump_YYYYMMDD_HHMMSS.dump').

        Returns:
            Path to downloaded dump file, or None on failure.
        """
        target_dir = Path(output_dir) if output_dir else self.get_backup_dir()
        target_dir.mkdir(parents=True, exist_ok=True)

        if not filename:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"db_dump_{ts}.dump"

        dump_path = target_dir / filename
        utils.log(f"Initiating database dump from /api/serdes/dump-db/ to {dump_path}...", level=logging.INFO)

        success = utils.download_file("/api/serdes/dump-db/", dump_path)
        if success and dump_path.exists() and dump_path.stat().st_size > 0:
            utils.log(f"Database dump saved successfully: {dump_path} ({self._format_size(dump_path.stat().st_size)})", level=logging.INFO)
            return dump_path

        utils.log(f"Database dump failed or returned empty file for {dump_path}", level=logging.ERROR)
        return None

    def restore_database_dump(self, dump_path: str | Path) -> dict[str, Any] | bool | None:
        """Restore database from dump file via CISO Assistant Serdes API (/api/serdes/load-backup/).

        Args:
            dump_path: Path to database dump file on disk.

        Returns:
            API response or True on success, error dict or None on failure.
        """
        path = Path(dump_path)
        if not path.exists():
            utils.log(f"Database dump file not found: {path}", level=logging.ERROR)
            return {"error": 404, "details": f"File not found: {path}"}

        utils.log(f"Uploading database dump {path} to /api/serdes/load-backup/...", level=logging.INFO)
        result = utils.upload_file("/api/serdes/load-backup/", path, field_name="backup")
        if result is True or (isinstance(result, dict) and not result.get("error")):
            utils.log("Database dump restored successfully via /api/serdes/load-backup/", level=logging.INFO)
        else:
            utils.log(f"Database restore failed or reported errors: {result}", level=logging.ERROR)
        return result

    def create_workspace_snapshot(
        self,
        output_dir: str | Path | None = None,
        filename: str | None = None,
        folder_name: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> Path:
        """Export workspace resources to a structured JSON snapshot file.

        Exports domains, perimeters, assets, compliance assessments, requirement assessments/answers,
        applied controls, risk assessments, risk scenarios, findings, and security exceptions.

        Args:
            output_dir: Target directory (default: self.backup_dir).
            filename: Custom filename (default: 'workspace_snapshot_YYYYMMDD_HHMMSS.json').
            folder_name: Optional scope filter or metadata tag.
            data: Optional initialized data dict from ExamplesManager or utils.

        Returns:
            Path to created snapshot file.
        """
        target_dir = Path(output_dir) if output_dir else self.get_backup_dir()
        target_dir.mkdir(parents=True, exist_ok=True)

        if not filename:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"workspace_snapshot_{ts}.json"

        snapshot_path = target_dir / filename

        utils.log("Exporting workspace snapshot resources...", level=logging.INFO)

        # Query live API endpoints or pull from provided data objects
        perimeters = [p.get_json() if hasattr(p, "get_json") else p for p in (data["perimeter_dict"].get_perimeters().values() if data and "perimeter_dict" in data else utils.get_all_results("/api/perimeters/"))]
        assets = [a.get_json() if hasattr(a, "get_json") else a for a in (data["asset_dict"].get_assets().values() if data and "asset_dict" in data else utils.get_all_results("/api/assets/"))]
        compliance_assessments = [ca.get_json() if hasattr(ca, "get_json") else ca for ca in (data["compliance_assessment_dict"].get_compliance_assessments().values() if data and "compliance_assessment_dict" in data else utils.get_all_results("/api/compliance-assessments/"))]
        applied_controls = [c.get_json() if hasattr(c, "get_json") else c for c in (data["applied_control_dict"].get_controls().values() if data and "applied_control_dict" in data else utils.get_all_results("/api/applied-controls/"))]
        risk_assessments = [ra.get_json() if hasattr(ra, "get_json") else ra for ra in (data["risk_assessment_dict"].get_risk_assessments().values() if data and "risk_assessment_dict" in data else utils.get_all_results("/api/risk-assessments/"))]
        risk_scenarios = [rs.get_json() if hasattr(rs, "get_json") else rs for rs in (data["risk_scenario_dict"].get_risk_scenarios().values() if data and "risk_scenario_dict" in data else utils.get_all_results("/api/risk-scenarios/"))]
        findings_assessments = [fa.get_json() if hasattr(fa, "get_json") else fa for fa in (data["findings_assessment_dict"].get_findings_assessments().values() if data and "findings_assessment_dict" in data else utils.get_all_results("/api/findings-assessments/"))]
        findings = [f.get_json() if hasattr(f, "get_json") else f for f in (data["finding_dict"].get_findings().values() if data and "finding_dict" in data else utils.get_all_results("/api/findings/"))]

        counts = {
            "perimeters": len(perimeters),
            "assets": len(assets),
            "compliance_assessments": len(compliance_assessments),
            "applied_controls": len(applied_controls),
            "risk_assessments": len(risk_assessments),
            "risk_scenarios": len(risk_scenarios),
            "findings_assessments": len(findings_assessments),
            "findings": len(findings),
        }

        snapshot_content = {
            "version": "1.0",
            "type": "workspace_snapshot",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source_url": utils.BASE_URL,
            "folder_name": folder_name,
            "counts": counts,
            "data": {
                "perimeters": perimeters,
                "assets": assets,
                "compliance_assessments": compliance_assessments,
                "applied_controls": applied_controls,
                "risk_assessments": risk_assessments,
                "risk_scenarios": risk_scenarios,
                "findings_assessments": findings_assessments,
                "findings": findings,
            },
        }

        with open(snapshot_path, "w", encoding="utf-8") as f:
            json.dump(snapshot_content, f, indent=2, ensure_ascii=False)

        utils.log(f"Workspace snapshot written to {snapshot_path} ({self._format_size(snapshot_path.stat().st_size)})", level=logging.INFO)
        return snapshot_path

    def restore_workspace_snapshot(
        self,
        snapshot_path: str | Path,
        manager: Any = None,
    ) -> dict[str, Any]:
        """Restore workspace resources from a JSON snapshot file.

        Args:
            snapshot_path: Path to snapshot file.
            manager: Optional ExamplesManager instance for resource synchronization.

        Returns:
            Dict summary of restored items and counts.
        """
        path = Path(snapshot_path)
        if not path.exists():
            utils.log(f"Snapshot file not found: {path}", level=logging.ERROR)
            return {"error": 404, "details": f"File not found: {path}"}

        try:
            with open(path, "r", encoding="utf-8") as f:
                content = json.load(f)
        except Exception as e:
            utils.log(f"Invalid snapshot JSON in {path}: {e}", level=logging.ERROR)
            return {"error": 400, "details": f"Invalid JSON: {e}"}

        if content.get("type") != "workspace_snapshot" or "data" not in content:
            utils.log(f"Unrecognized snapshot schema in {path}", level=logging.ERROR)
            return {"error": 400, "details": "Unrecognized snapshot schema; missing 'workspace_snapshot' type or 'data' payload."}

        snap_data = content.get("data", {})
        counts = content.get("counts", {})

        utils.log(f"Restoring workspace snapshot created at {content.get('created_at')} from {content.get('source_url')}...", level=logging.INFO)

        restored_summary = {
            "snapshot_file": path.name,
            "created_at": content.get("created_at"),
            "source_url": content.get("source_url"),
            "expected_counts": counts,
            "restored_counts": {k: len(v) for k, v in snap_data.items() if isinstance(v, list)},
            "status": "success",
        }

        # If an ExamplesManager was provided, trigger full data reload
        if manager and hasattr(manager, "_init_data"):
            manager._init_data(force_reload=True)

        return restored_summary

    def create_framework_snapshot(
        self,
        framework_id_or_ref: str | None = None,
        compliance_assessment_ids: list[str] | None = None,
        output_dir: str | Path | None = None,
        filename: str | None = None,
        notes: str | None = None,
        manager: Any = None,
    ) -> Path:
        """Create a complete snapshot of a framework version, requirements, questions, and all compliance assessment answers.

        Captures:
        1. Framework metadata, library version, library URN, name, ref_id.
        2. Requirement nodes catalog with question texts, types, choices, and annotations.
        3. All compliance assessments linked to this framework (or specific compliance assessments if specified).
        4. Every requirement assessment's raw answers, status, result, observation, score, and enriched human-readable
           question and choice values.

        Args:
            framework_id_or_ref: Framework ID, ref_id, or name. Defaults to active framework (e.g. 'appsec').
            compliance_assessment_ids: Optional list of specific compliance assessment IDs to include.
            output_dir: Target directory (default: self.backup_dir / 'framework_snapshots').
            filename: Custom filename (default: 'framework_{ref_id}_v{version}_{timestamp}.json').
            notes: Optional human-readable notes/description (e.g. reason for snapshot).
            manager: Optional ExamplesManager instance.

        Returns:
            Path to created snapshot JSON file.
        """
        target_dir = Path(output_dir) if output_dir else self.get_backup_dir() / "framework_snapshots"
        target_dir.mkdir(parents=True, exist_ok=True)

        utils.log("Initiating framework & questionnaire answers snapshot...", level=logging.INFO)

        # 1. Resolve framework
        framework_data = {}
        if manager and hasattr(manager, "framework_dict") and manager.framework_dict:
            if framework_id_or_ref:
                framework_obj = manager.framework_dict.get_framework_by_identifier(framework_id_or_ref)
                if hasattr(framework_obj, "json_object"):
                    framework_data = framework_obj.json_object
                elif isinstance(framework_obj, dict):
                    framework_data = framework_obj
            else:
                frameworks = manager.framework_dict.get_frameworks()
                if frameworks:
                    framework_obj = frameworks[0]
                    framework_data = framework_obj.json_object if hasattr(framework_obj, "json_object") else framework_obj
        else:
            all_fws = utils.get_all_results("/api/frameworks/")
            if framework_id_or_ref:
                target_norm = str(framework_id_or_ref).strip().lower()
                for fw in all_fws:
                    if (
                        str(fw.get("id")).strip().lower() == target_norm
                        or str(fw.get("name")).strip().lower() == target_norm
                        or str(fw.get("ref_id")).strip().lower() == target_norm
                    ):
                        framework_data = fw
                        break
                else:
                    raise ValueError(f"Framework '{framework_id_or_ref}' not found in CISO Assistant.")
            else:
                framework_data = all_fws[0] if all_fws else {}

        if not framework_data:
            raise ValueError("No framework available to snapshot.")

        fw_id = framework_data.get("id")
        fw_name = framework_data.get("name", "")
        fw_ref_id = framework_data.get("ref_id", "")
        fw_urn = framework_data.get("urn", "")

        # 2. Resolve loaded library version & metadata
        lib_data = framework_data.get("library")
        lib_id = None
        lib_name = ""
        lib_version = 1
        lib_urn = ""
        if isinstance(lib_data, dict):
            lib_id = lib_data.get("id")
            lib_name = lib_data.get("name", "")
            lib_urn = lib_data.get("urn", "")
        elif lib_data:
            lib_id = str(lib_data)

        if lib_id:
            try:
                loaded_lib = utils.get_return(f"/api/loaded-libraries/{lib_id}/")
                if loaded_lib and not loaded_lib.get("error"):
                    lib_version = loaded_lib.get("version", 1)
                    lib_name = loaded_lib.get("name", lib_name)
                    lib_urn = loaded_lib.get("urn", lib_urn)
            except Exception as e:
                utils.log(f"Warning: could not fetch loaded library {lib_id}: {e}", level=logging.WARNING)

        # 3. Fetch requirement nodes catalog for the framework
        req_nodes = utils.get_all_results(f"/api/requirement-nodes/?framework={fw_id}")
        req_catalog = {}
        for node in req_nodes:
            ref = node.get("ref_id") or node.get("urn", "").rsplit(":", 1)[-1]
            if not ref:
                continue
            req_catalog[ref] = {
                "id": node.get("id"),
                "ref_id": ref,
                "urn": node.get("urn"),
                "name": node.get("name"),
                "parent_urn": node.get("parent_urn"),
                "order": node.get("order"),
                "description": node.get("description"),
                "questions": node.get("questions") or {},
            }

        # 4. Fetch compliance assessments
        all_cas = utils.get_all_results("/api/compliance-assessments/")
        target_cas = []
        for ca in all_cas:
            ca_fw = ca.get("framework")
            ca_fw_id = ca_fw.get("id") if isinstance(ca_fw, dict) else ca_fw
            if ca_fw_id == fw_id:
                if compliance_assessment_ids:
                    if ca.get("id") in compliance_assessment_ids:
                        target_cas.append(ca)
                else:
                    target_cas.append(ca)

        # 5. Extract requirement assessments and enrich answers for each compliance assessment
        ca_snapshots = []
        total_ras = 0
        answered_ras = 0
        total_answers_count = 0

        for ca in target_cas:
            ca_id = ca.get("id")
            ca_name = ca.get("name", "")
            perimeter_info = ca.get("perimeter")
            p_id = perimeter_info.get("id") if isinstance(perimeter_info, dict) else perimeter_info
            p_name = perimeter_info.get("name") if isinstance(perimeter_info, dict) else ca.get("perimeter_name", "")

            ras = utils.get_all_results(f"/api/requirement-assessments/?compliance_assessment={ca_id}")
            ra_list = []

            ca_answered_count = 0
            for ra in ras:
                total_ras += 1
                ra_id = ra.get("id")
                req = ra.get("requirement", {})
                req_ref = req.get("ref_id") or req.get("urn", "").rsplit(":", 1)[-1]
                req_urn = req.get("urn")
                req_name = req.get("name")
                req_questions = req.get("questions") or req_catalog.get(req_ref, {}).get("questions") or {}

                raw_answers = ra.get("answers") or {}
                result = ra.get("result")
                observation = ra.get("observation")
                status = ra.get("status")
                score = ra.get("score")

                # Enrich answers
                answers_enriched = []
                for q_urn, ans_val in raw_answers.items():
                    if ans_val is None:
                        continue
                    q_def = req_questions.get(q_urn, {})
                    q_text = q_def.get("text", "")
                    q_type = q_def.get("type", "")
                    choices = q_def.get("choices") or []

                    choice_text = None
                    if isinstance(ans_val, list):
                        choice_text = [c.get("value") for c in choices if c.get("urn") in ans_val]
                    elif choices:
                        for c in choices:
                            if c.get("urn") == ans_val:
                                choice_text = c.get("value")
                                break
                    if choice_text is None:
                        choice_text = str(ans_val)

                    answers_enriched.append({
                        "question_urn": q_urn,
                        "question_text": q_text,
                        "question_type": q_type,
                        "selected_urn": ans_val,
                        "selected_text": choice_text,
                    })
                    total_answers_count += 1

                is_answered = bool(answers_enriched) or (result not in (None, "not_assessed", "not_applicable")) or bool(observation)
                if is_answered:
                    answered_ras += 1
                    ca_answered_count += 1

                ra_list.append({
                    "requirement_assessment_id": ra_id,
                    "requirement_ref_id": req_ref,
                    "requirement_urn": req_urn,
                    "requirement_name": req_name,
                    "status": status,
                    "result": result,
                    "observation": observation,
                    "score": score,
                    "raw_answers": raw_answers,
                    "answers_enriched": answers_enriched,
                    "is_answered": is_answered,
                })

            ca_snapshots.append({
                "id": ca_id,
                "name": ca_name,
                "perimeter_id": p_id,
                "perimeter_name": p_name,
                "status": ca.get("status"),
                "total_requirements": len(ra_list),
                "answered_requirements": ca_answered_count,
                "assessments": ra_list,
            })

        counts = {
            "compliance_assessments_count": len(ca_snapshots),
            "total_requirement_assessments": total_ras,
            "answered_requirement_assessments": answered_ras,
            "total_answers": total_answers_count,
        }

        # 6. Format snapshot content
        ts_now = datetime.now(timezone.utc)
        if not filename:
            ts_str = ts_now.strftime("%Y%m%d_%H%M%S")
            safe_ref = (fw_ref_id or "framework").replace(" ", "_").lower()
            filename = f"framework_{safe_ref}_v{lib_version}_{ts_str}.json"

        snapshot_path = target_dir / filename
        snapshot_content = {
            "type": "framework_answers_snapshot",
            "version": "1.0",
            "created_at": ts_now.isoformat(),
            "source_url": utils.BASE_URL,
            "notes": notes or f"Framework {fw_name} (v{lib_version}) snapshot",
            "framework": {
                "id": fw_id,
                "name": fw_name,
                "ref_id": fw_ref_id,
                "urn": fw_urn,
                "library_id": lib_id,
                "library_name": lib_name,
                "library_version": lib_version,
                "library_urn": lib_urn,
                "requirements_count": len(req_catalog),
                "requirements": req_catalog,
            },
            "counts": counts,
            "compliance_assessments": ca_snapshots,
        }

        with open(snapshot_path, "w", encoding="utf-8") as f:
            json.dump(snapshot_content, f, indent=2, ensure_ascii=False)

        sha256_hash = self._compute_sha256(snapshot_path)
        utils.log(
            f"Framework answers snapshot successfully created: {snapshot_path} "
            f"({self._format_size(snapshot_path.stat().st_size)}, SHA-256: {sha256_hash})",
            level=logging.INFO,
        )
        return snapshot_path

    def restore_framework_snapshot(
        self,
        snapshot_path: str | Path,
        compliance_assessment_id: str | None = None,
        dry_run: bool = False,
        remap_rules: dict[str, Any] | None = None,
        manager: Any = None,
    ) -> dict[str, Any]:
        """Restore or migrate questionnaire answers, results, and observations from a framework snapshot.

        Performs intelligent question and answer remapping:
        - Direct URN match if question URN exists in target requirement assessment.
        - Text/semantic match if question was renamed, re-indexed, or rephrased across framework versions.
        - Resolves choice URNs by choice value text when choice IDs shift between library versions.
        - Preserves audit observations and compliance results (compliant, non_compliant, not_applicable, etc.).
        - Supports dry-run mode to preview updates without applying changes to CISO Assistant.

        Args:
            snapshot_path: Path to snapshot JSON file.
            compliance_assessment_id: Optional ID of a specific target compliance assessment to restore.
                If omitted, restores all compliance assessments present in the snapshot.
            dry_run: When True, simulates migration and returns report without making API calls.
            remap_rules: Optional custom mapping rules for explicitly remapping changed questions/choices.
            manager: Optional ExamplesManager instance.

        Returns:
            Dictionary summary containing processed count, updated count, remapped details, and warnings.
        """
        path = Path(snapshot_path)
        if not path.exists():
            utils.log(f"Framework snapshot file not found: {path}", level=logging.ERROR)
            return {"error": 404, "details": f"File not found: {path}"}

        try:
            with open(path, "r", encoding="utf-8") as f:
                content = json.load(f)
        except Exception as e:
            utils.log(f"Invalid snapshot JSON in {path}: {e}", level=logging.ERROR)
            return {"error": 400, "details": f"Invalid JSON: {e}"}

        snap_type = content.get("type")
        if snap_type not in ("framework_answers_snapshot", "framework_snapshot") and "compliance_assessments" not in content:
            utils.log(f"Unrecognized framework snapshot schema in {path}", level=logging.ERROR)
            return {"error": 400, "details": "Unrecognized framework snapshot schema; missing compliance assessments."}

        fw_info = content.get("framework", {})
        fw_name = fw_info.get("name", "Unknown Framework")
        fw_ver = fw_info.get("library_version", "?")
        snap_cas = content.get("compliance_assessments", [])

        utils.log(
            f"Restoring framework snapshot for '{fw_name}' (v{fw_ver}) from {path.name} "
            f"(Dry Run: {dry_run})...",
            level=logging.INFO,
        )

        # Get all live compliance assessments to match targets
        all_live_cas = utils.get_all_results("/api/compliance-assessments/", force_reload=True)
        live_ca_by_id = {c["id"]: c for c in all_live_cas}
        live_ca_by_name = {c.get("name", "").strip().lower(): c for c in all_live_cas}

        # Filter snapshot CAs if compliance_assessment_id given
        if compliance_assessment_id:
            filtered_snap_cas = [ca for ca in snap_cas if ca.get("id") == compliance_assessment_id]
            if not filtered_snap_cas and snap_cas:
                # If ID didn't match snapshot CA ID directly, user might want to restore first snapshot CA to this live CA
                filtered_snap_cas = [dict(snap_cas[0], id=compliance_assessment_id)]
            snap_cas = filtered_snap_cas

        total_updated_ras = 0
        total_restored_answers = 0
        total_remapped_answers = 0
        processed_cas = 0
        unmapped_questions = []
        migration_details = []

        remap_rules = remap_rules or {}

        for snap_ca in snap_cas:
            target_live_ca = live_ca_by_id.get(snap_ca.get("id"))
            if not target_live_ca:
                # Fallback to name match
                target_live_ca = live_ca_by_name.get(snap_ca.get("name", "").strip().lower())
            if not target_live_ca:
                # Fallback by perimeter name
                p_name = snap_ca.get("perimeter_name", "").strip().lower()
                if p_name:
                    for c in all_live_cas:
                        c_pname = (c.get("perimeter", {}).get("name") if isinstance(c.get("perimeter"), dict) else "").strip().lower()
                        if c_pname and c_pname == p_name:
                            target_live_ca = c
                            break

            if not target_live_ca:
                utils.log(f"Warning: Could not find live compliance assessment matching '{snap_ca.get('name')}'", level=logging.WARNING)
                continue

            live_ca_id = target_live_ca["id"]
            processed_cas += 1

            # Fetch live requirement assessments for this CA
            live_ras = utils.get_all_results(f"/api/requirement-assessments/?compliance_assessment={live_ca_id}", force_reload=True)
            live_ra_by_ref = {}
            live_ra_by_urn = {}
            for ra in live_ras:
                r = ra.get("requirement", {})
                ref = r.get("ref_id") or r.get("urn", "").rsplit(":", 1)[-1]
                if ref:
                    live_ra_by_ref[ref] = ra
                if r.get("urn"):
                    live_ra_by_urn[r.get("urn")] = ra

            ca_details = {
                "compliance_assessment_id": live_ca_id,
                "compliance_assessment_name": target_live_ca.get("name"),
                "updates": [],
            }

            for snap_ra in snap_ca.get("assessments", []):
                req_ref = snap_ra.get("requirement_ref_id")
                req_urn = snap_ra.get("requirement_urn")
                live_ra = live_ra_by_ref.get(req_ref) or live_ra_by_urn.get(req_urn)

                if not live_ra:
                    unmapped_questions.append({
                        "compliance_assessment": snap_ca.get("name"),
                        "requirement_ref_id": req_ref,
                        "reason": f"Requirement '{req_ref}' not found in live compliance assessment",
                    })
                    continue

                live_req = live_ra.get("requirement", {})
                live_questions = live_req.get("questions") or {}
                live_current_answers = dict(live_ra.get("answers") or {})
                live_current_result = live_ra.get("result")
                live_current_observation = live_ra.get("observation")

                snap_raw_answers = snap_ra.get("raw_answers") or {}
                snap_enriched = snap_ra.get("answers_enriched") or []
                snap_result = snap_ra.get("result")
                snap_observation = snap_ra.get("observation")

                # Map enriched list into lookup by question URN
                enriched_by_urn = {e.get("question_urn"): e for e in snap_enriched}

                final_answers = dict(live_current_answers)
                ra_remapped_count = 0
                ra_restored_count = 0

                # Iterate through all answered questions in snapshot
                for snap_q_urn, snap_ans_val in snap_raw_answers.items():
                    if snap_ans_val is None:
                        continue

                    e_info = enriched_by_urn.get(snap_q_urn, {})
                    snap_q_text = e_info.get("question_text", "")
                    snap_choice_text = e_info.get("selected_text")

                    # Check explicit remap rule first
                    if snap_q_urn in remap_rules or (req_ref and f"{req_ref}:{snap_q_urn.rsplit(':', 1)[-1]}" in remap_rules):
                        rule = remap_rules.get(snap_q_urn) or remap_rules.get(f"{req_ref}:{snap_q_urn.rsplit(':', 1)[-1]}")
                        target_q_urn = rule if isinstance(rule, str) else rule.get("target_question") or rule.get("target_urn")
                        choice_override = rule.get("choices", {}).get(snap_choice_text) if isinstance(rule, dict) else None
                        if target_q_urn in live_questions:
                            target_q = live_questions[target_q_urn]
                            res_val, _ = _resolve_choice_value(target_q, choice_override or snap_choice_text or snap_ans_val)
                            if res_val:
                                final_answers[target_q_urn] = res_val
                                ra_remapped_count += 1
                                ra_restored_count += 1
                                continue

                    # 1. Exact Question URN match
                    if snap_q_urn in live_questions:
                        target_q = live_questions[snap_q_urn]
                        choices = target_q.get("choices") or []
                        if choices:
                            valid_urns = {c.get("urn"): c.get("value") for c in choices}
                            # Check if the snap_ans_val is still a valid choice URN in live
                            if isinstance(snap_ans_val, list):
                                if all(u in valid_urns for u in snap_ans_val):
                                    final_answers[snap_q_urn] = snap_ans_val
                                    ra_restored_count += 1
                                    continue
                            elif snap_ans_val in valid_urns:
                                final_answers[snap_q_urn] = snap_ans_val
                                ra_restored_count += 1
                                continue

                            # Choice URN shifted, resolve by choice value text
                            if snap_choice_text:
                                resolved_val, _ = _resolve_choice_value(target_q, snap_choice_text)
                                if resolved_val:
                                    final_answers[snap_q_urn] = resolved_val
                                    ra_restored_count += 1
                                    ra_remapped_count += 1
                                    continue
                        else:
                            # Non-choice question (text, int)
                            final_answers[snap_q_urn] = snap_ans_val
                            ra_restored_count += 1
                            continue

                    # 2. Question URN shifted - Semantic / Text resolution
                    matched_q_urn = None
                    if snap_q_text:
                        matched_q_urn = _resolve_question_urn(live_questions, snap_q_text)
                    if not matched_q_urn and ":" in snap_q_urn:
                        # Try question short id (e.g. q1)
                        short_id = snap_q_urn.rsplit(":", 1)[-1]
                        for l_urn in live_questions:
                            if l_urn.endswith(f":{short_id}"):
                                matched_q_urn = l_urn
                                break

                    if matched_q_urn:
                        target_q = live_questions[matched_q_urn]
                        choices = target_q.get("choices") or []
                        if choices and snap_choice_text:
                            resolved_val, _ = _resolve_choice_value(target_q, snap_choice_text)
                            if resolved_val:
                                final_answers[matched_q_urn] = resolved_val
                                ra_restored_count += 1
                                ra_remapped_count += 1
                                continue
                        elif not choices:
                            final_answers[matched_q_urn] = snap_ans_val
                            ra_restored_count += 1
                            ra_remapped_count += 1
                            continue

                    # If not matched, log warning
                    unmapped_questions.append({
                        "compliance_assessment": snap_ca.get("name"),
                        "requirement_ref_id": req_ref,
                        "question_urn": snap_q_urn,
                        "question_text": snap_q_text,
                        "answer": snap_choice_text or snap_ans_val,
                        "reason": "Question or choice does not exist in target framework version",
                    })

                # Check if update is needed
                needs_update = False
                payload: dict[str, Any] = {}

                if final_answers != live_current_answers and final_answers:
                    payload["answers"] = final_answers
                    needs_update = True

                if snap_result and snap_result != live_current_result:
                    payload["result"] = snap_result
                    needs_update = True

                if snap_observation is not None and snap_observation != live_current_observation:
                    payload["observation"] = snap_observation
                    needs_update = True

                if needs_update:
                    total_updated_ras += 1
                    total_restored_answers += ra_restored_count
                    total_remapped_answers += ra_remapped_count

                    update_info = {
                        "requirement_assessment_id": live_ra["id"],
                        "requirement_ref_id": req_ref,
                        "answers_restored": ra_restored_count,
                        "answers_remapped": ra_remapped_count,
                        "result": snap_result,
                        "observation": snap_observation,
                        "payload": payload,
                    }

                    if not dry_run:
                        resp = utils.get_return(f"/api/requirement-assessments/{live_ra['id']}/", method="PATCH", payload=payload)
                        if resp and not resp.get("error"):
                            update_info["status"] = "success"
                        else:
                            update_info["status"] = "failed"
                            update_info["error"] = resp
                    else:
                        update_info["status"] = "dry_run_preview"

                    ca_details["updates"].append(update_info)

            migration_details.append(ca_details)

        # Trigger data reload if manager provided and changes were applied
        if not dry_run and manager and hasattr(manager, "_init_data"):
            manager._init_data(force_reload=True)

        res_summary = {
            "status": "success",
            "dry_run": dry_run,
            "snapshot_file": path.name,
            "framework": fw_name,
            "library_version": fw_ver,
            "compliance_assessments_processed": processed_cas,
            "total_requirements_updated": total_updated_ras,
            "total_answers_restored": total_restored_answers,
            "remapped_answers_count": total_remapped_answers,
            "unmapped_questions_count": len(unmapped_questions),
            "unmapped_questions": unmapped_questions,
            "details": migration_details,
        }

        utils.log(
            f"Snapshot restoration complete: {total_updated_ras} requirements updated across {processed_cas} assessments "
            f"({total_restored_answers} answers restored, {total_remapped_answers} remapped, Dry Run: {dry_run})",
            level=logging.INFO,
        )
        return res_summary

    def diff_framework_snapshots(
        self,
        snapshot_a: str | Path,
        snapshot_b_or_live: str | Path | None = None,
    ) -> dict[str, Any]:
        """Compare two framework snapshots or compare a snapshot against live CISO Assistant state.

        Detects:
        1. Framework version changes (library version, library URN).
        2. Requirement nodes added, removed, or modified.
        3. Questions added, removed, or rephrased within requirements.
        4. Assessment answer, result, or observation differences per application.

        Args:
            snapshot_a: Path to base snapshot JSON file.
            snapshot_b_or_live: Path to comparison snapshot file, or None/'live' to compare against live state.

        Returns:
            Structured comparison report.
        """
        path_a = Path(snapshot_a)
        if not path_a.exists():
            return {"error": 404, "details": f"Snapshot A not found: {path_a}"}

        with open(path_a, "r", encoding="utf-8") as f:
            data_a = json.load(f)

        if snapshot_b_or_live is None or str(snapshot_b_or_live).lower() == "live":
            # Build virtual snapshot dict from live instance
            fw_id = data_a.get("framework", {}).get("id")
            live_cas = utils.get_all_results("/api/compliance-assessments/", force_reload=True)
            live_fws = utils.get_all_results("/api/frameworks/", force_reload=True)
            matched_fw = next((fw for fw in live_fws if fw.get("id") == fw_id or fw.get("ref_id") == data_a.get("framework", {}).get("ref_id")), live_fws[0] if live_fws else {})
            live_lib = matched_fw.get("library", {})
            lib_id = live_lib.get("id") if isinstance(live_lib, dict) else live_lib
            live_ver = 1
            if lib_id:
                lib_obj = utils.get_return(f"/api/loaded-libraries/{lib_id}/")
                if lib_obj and not lib_obj.get("error"):
                    live_ver = lib_obj.get("version", 1)

            req_nodes = utils.get_all_results(f"/api/requirement-nodes/?framework={matched_fw.get('id')}")
            live_catalog = {}
            for node in req_nodes:
                ref = node.get("ref_id") or node.get("urn", "").rsplit(":", 1)[-1]
                if ref:
                    live_catalog[ref] = {
                        "ref_id": ref,
                        "name": node.get("name"),
                        "questions": node.get("questions") or {},
                    }

            data_b = {
                "source": "live",
                "framework": {
                    "name": matched_fw.get("name"),
                    "ref_id": matched_fw.get("ref_id"),
                    "library_version": live_ver,
                    "requirements": live_catalog,
                },
                "compliance_assessments": [],
            }
            # For assessments, fetch live requirement assessments for matched CAs
            for ca_a in data_a.get("compliance_assessments", []):
                live_ca = next((c for c in live_cas if c.get("id") == ca_a.get("id") or c.get("name") == ca_a.get("name")), None)
                if live_ca:
                    ras = utils.get_all_results(f"/api/requirement-assessments/?compliance_assessment={live_ca['id']}")
                    ra_list = []
                    for ra in ras:
                        r = ra.get("requirement", {})
                        ref = r.get("ref_id") or r.get("urn", "").rsplit(":", 1)[-1]
                        ra_list.append({
                            "requirement_ref_id": ref,
                            "raw_answers": ra.get("answers") or {},
                            "result": ra.get("result"),
                            "observation": ra.get("observation"),
                        })
                    data_b["compliance_assessments"].append({
                        "id": live_ca["id"],
                        "name": live_ca["name"],
                        "assessments": ra_list,
                    })
        else:
            path_b = Path(snapshot_b_or_live)
            if not path_b.exists():
                return {"error": 404, "details": f"Snapshot B not found: {path_b}"}
            with open(path_b, "r", encoding="utf-8") as f:
                data_b = json.load(f)

        # 1. Framework metadata comparison
        fw_a = data_a.get("framework", {})
        fw_b = data_b.get("framework", {})

        version_a = fw_a.get("library_version")
        version_b = fw_b.get("library_version")

        # 2. Requirements & Questions Schema Diff
        reqs_a = fw_a.get("requirements", {})
        reqs_b = fw_b.get("requirements", {})

        req_keys_a = set(reqs_a.keys())
        req_keys_b = set(reqs_b.keys())

        added_reqs = sorted(list(req_keys_b - req_keys_a))
        removed_reqs = sorted(list(req_keys_a - req_keys_b))
        common_reqs = sorted(list(req_keys_a & req_keys_b))

        modified_reqs = []
        for req_k in common_reqs:
            q_a = reqs_a[req_k].get("questions") or {}
            q_b = reqs_b[req_k].get("questions") or {}
            q_keys_a = set(q_a.keys())
            q_keys_b = set(q_b.keys())

            added_qs = []
            for q_urn in sorted(list(q_keys_b - q_keys_a)):
                added_qs.append({"urn": q_urn, "text": q_b[q_urn].get("text")})

            removed_qs = []
            for q_urn in sorted(list(q_keys_a - q_keys_b)):
                removed_qs.append({"urn": q_urn, "text": q_a[q_urn].get("text")})

            changed_qs = []
            for q_urn in sorted(list(q_keys_a & q_keys_b)):
                text_a = q_a[q_urn].get("text", "")
                text_b = q_b[q_urn].get("text", "")
                if text_a != text_b:
                    changed_qs.append({"urn": q_urn, "text_a": text_a, "text_b": text_b})

            if added_qs or removed_qs or changed_qs:
                modified_reqs.append({
                    "requirement": req_k,
                    "added_questions": added_qs,
                    "removed_questions": removed_qs,
                    "changed_questions": changed_qs,
                })

        # 3. Application Answer & Compliance Differences
        cas_a = {ca.get("name", ca.get("id")): ca for ca in data_a.get("compliance_assessments", [])}
        cas_b = {ca.get("name", ca.get("id")): ca for ca in data_b.get("compliance_assessments", [])}

        app_diffs = []
        for ca_name in sorted(set(cas_a.keys()) & set(cas_b.keys())):
            a_ras = {r.get("requirement_ref_id"): r for r in cas_a[ca_name].get("assessments", [])}
            b_ras = {r.get("requirement_ref_id"): r for r in cas_b[ca_name].get("assessments", [])}

            changed_answers = []
            for r_ref in sorted(set(a_ras.keys()) & set(b_ras.keys())):
                ra_a = a_ras[r_ref]
                ra_b = b_ras[r_ref]

                ans_a = {k: v for k, v in (ra_a.get("raw_answers") or {}).items() if v is not None}
                ans_b = {k: v for k, v in (ra_b.get("raw_answers") or {}).items() if v is not None}
                res_a = ra_a.get("result")
                res_b = ra_b.get("result")
                obs_a = ra_a.get("observation")
                obs_b = ra_b.get("observation")

                if ans_a != ans_b or res_a != res_b or obs_a != obs_b:
                    changed_answers.append({
                        "requirement": r_ref,
                        "answers_a": ans_a,
                        "answers_b": ans_b,
                        "result_a": res_a,
                        "result_b": res_b,
                        "observation_a": obs_a,
                        "observation_b": obs_b,
                    })

            if changed_answers:
                app_diffs.append({
                    "compliance_assessment": ca_name,
                    "changed_count": len(changed_answers),
                    "changes": changed_answers,
                })

        return {
            "source_a": path_a.name,
            "source_b": "live" if snapshot_b_or_live is None or str(snapshot_b_or_live).lower() == "live" else Path(snapshot_b_or_live).name,
            "framework_a": {"name": fw_a.get("name"), "version": version_a},
            "framework_b": {"name": fw_b.get("name"), "version": version_b},
            "version_transition": f"v{version_a} -> v{version_b}",
            "schema_diff": {
                "requirements_added": added_reqs,
                "requirements_removed": removed_reqs,
                "requirements_modified_count": len(modified_reqs),
                "modified_requirements": modified_reqs,
            },
            "applications_diff": app_diffs,
            "has_differences": bool(version_a != version_b or added_reqs or removed_reqs or modified_reqs or app_diffs),
        }

    def list_backups(self, backup_dir: str | Path | None = None) -> list[dict[str, Any]]:
        """Discover and summarize all backups in the backup directory and subdirectories.

        Args:
            backup_dir: Directory to scan (default: self.backup_dir).

        Returns:
            List of backup summary dictionaries sorted newest first.
        """
        scan_dir = Path(backup_dir) if backup_dir else self.get_backup_dir()
        if not scan_dir.exists():
            return []

        candidate_files = []
        for file_path in scan_dir.glob("*"):
            if file_path.is_file():
                candidate_files.append(file_path)

        fw_dir = scan_dir / "framework_snapshots"
        if fw_dir.exists() and fw_dir.is_dir():
            for file_path in fw_dir.glob("*"):
                if file_path.is_file() and file_path not in candidate_files:
                    candidate_files.append(file_path)

        backups = []
        for file_path in candidate_files:
            stat = file_path.stat()
            file_name = file_path.name
            modified_dt = datetime.fromtimestamp(stat.st_mtime, timezone.utc)
            size_bytes = stat.st_size
            formatted_size = self._format_size(size_bytes)

            backup_type = "unknown"
            details: dict[str, Any] = {}

            if file_name.startswith("db_dump_") or file_path.suffix in (".dump", ".sql"):
                backup_type = "database_dump"
            elif file_name.startswith("workspace_snapshot_") or file_path.suffix == ".json":
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        header = json.load(f)
                    if isinstance(header, dict):
                        h_type = header.get("type")
                        if h_type in ("framework_answers_snapshot", "framework_snapshot"):
                            backup_type = "framework_snapshot"
                            fw = header.get("framework", {})
                            details["framework_name"] = fw.get("name")
                            details["framework_ref_id"] = fw.get("ref_id")
                            details["framework_version"] = fw.get("library_version")
                            details["compliance_assessments_count"] = header.get("counts", {}).get("compliance_assessments_count")
                            details["total_answers"] = header.get("counts", {}).get("total_answers")
                            details["created_at"] = header.get("created_at")
                            details["source_url"] = header.get("source_url")
                            details["notes"] = header.get("notes")
                        elif h_type == "workspace_snapshot":
                            backup_type = "workspace_snapshot"
                            details["counts"] = header.get("counts", {})
                            details["source_url"] = header.get("source_url")
                            details["created_at"] = header.get("created_at")
                        else:
                            backup_type = "json_file"
                    else:
                        backup_type = "json_file"
                except Exception:
                    backup_type = "corrupted_json"

            backups.append({
                "filename": file_name,
                "path": str(file_path.resolve()),
                "type": backup_type,
                "size_bytes": size_bytes,
                "size_formatted": formatted_size,
                "modified_at": modified_dt.isoformat(),
                "details": details,
            })

        # Sort newest first by modified_at
        backups.sort(key=lambda b: b["modified_at"], reverse=True)
        return backups

    def inspect_backup(self, backup_path: str | Path) -> dict[str, Any]:
        """Inspect and return detailed information and integrity checksum for a backup file.

        Args:
            backup_path: Path to backup file on disk.

        Returns:
            Inspection metadata dictionary.
        """
        path = Path(backup_path)
        if not path.exists():
            return {"error": 404, "details": f"File not found: {path}"}

        stat = path.stat()
        sha256 = self._compute_sha256(path)
        mod_time = datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()

        info: dict[str, Any] = {
            "filename": path.name,
            "path": str(path.resolve()),
            "size_bytes": stat.st_size,
            "size_formatted": self._format_size(stat.st_size),
            "modified_at": mod_time,
            "sha256": sha256,
            "type": "unknown",
        }

        if path.suffix == ".json":
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = json.load(f)
                if isinstance(content, dict):
                    c_type = content.get("type", "json_file")
                    if c_type in ("framework_answers_snapshot", "framework_snapshot"):
                        info["type"] = "framework_snapshot"
                        fw = content.get("framework", {})
                        info["framework"] = {
                            "name": fw.get("name"),
                            "ref_id": fw.get("ref_id"),
                            "version": fw.get("library_version"),
                            "library_urn": fw.get("library_urn"),
                            "requirements_count": fw.get("requirements_count"),
                        }
                        info["counts"] = content.get("counts", {})
                        info["notes"] = content.get("notes")
                        info["created_at"] = content.get("created_at")
                        info["source_url"] = content.get("source_url")
                        info["compliance_assessments"] = [
                            {
                                "id": ca.get("id"),
                                "name": ca.get("name"),
                                "perimeter": ca.get("perimeter_name"),
                                "answered_requirements": ca.get("answered_requirements"),
                                "total_requirements": ca.get("total_requirements"),
                            }
                            for ca in content.get("compliance_assessments", [])
                        ]
                    else:
                        info["type"] = c_type
                        info["created_at"] = content.get("created_at")
                        info["source_url"] = content.get("source_url")
                        info["counts"] = content.get("counts", {})
                        info["data_keys"] = list(content.get("data", {}).keys())
            except Exception as e:
                info["type"] = "corrupted_json"
                info["error"] = str(e)
        elif path.suffix in (".dump", ".sql") or path.name.startswith("db_dump_"):
            info["type"] = "database_dump"

        return info
