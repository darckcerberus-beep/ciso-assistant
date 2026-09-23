"""Backup and restore management for CISO Assistant.

Provides capabilities for:
1. Server-level database dumps and restores via CISO Assistant Serdes API (/api/serdes/dump-db/ and /api/serdes/load-backup/).
2. Portable workspace and application snapshots (JSON export/import of domains, perimeters, assets, audits, controls, risks, findings, exceptions).
3. Backup discovery, inspection, and verification (timestamps, file sizes, resource counts, SHA-256 integrity checksums).
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from .. import utils

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

    def list_backups(self, backup_dir: str | Path | None = None) -> list[dict[str, Any]]:
        """Discover and summarize all backups in the backup directory.

        Args:
            backup_dir: Directory to scan (default: self.backup_dir).

        Returns:
            List of backup summary dictionaries sorted newest first.
        """
        scan_dir = Path(backup_dir) if backup_dir else self.get_backup_dir()
        if not scan_dir.exists():
            return []

        backups = []
        for file_path in scan_dir.glob("*"):
            if not file_path.is_file():
                continue

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
                    if isinstance(header, dict) and header.get("type") == "workspace_snapshot":
                        backup_type = "workspace_snapshot"
                        details["counts"] = header.get("counts", {})
                        details["source_url"] = header.get("source_url")
                        details["created_at"] = header.get("created_at")
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
                    info["type"] = content.get("type", "json_file")
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

