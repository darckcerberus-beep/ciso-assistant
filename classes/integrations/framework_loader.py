"""Framework loading, updating, and unloading management for CISO Assistant.

Provides capabilities for:
1. Automated pre-operation backups of existing data (workspace snapshot, database dump, or framework snapshot)
   before loading, updating, or unloading frameworks.
2. Loading frameworks from local definition files (YAML/YML or Excel XLSX).
3. Importing pre-packaged stored libraries from CISO Assistant's built-in catalog (375+ frameworks).
4. Safe re-loading, upgrading, and unloading of existing frameworks.
5. Discovery and status inspection of stored libraries and active frameworks.
"""

from datetime import datetime, timezone
import logging
from pathlib import Path
from typing import Any
import requests
import urllib3
import yaml

from keys import API_TOKEN, BASE_URL
from .. import utils
from .backup import BackupManager, DEFAULT_BACKUP_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
LOGGER = logging.getLogger(__name__)


class FrameworkLoader:
    """Manages loading, updating, uploading, and unloading frameworks in CISO Assistant
    with automated pre-operation backups of existing data.
    """

    def __init__(
        self,
        backup_manager: BackupManager | None = None,
        manager: Any | None = None,
    ):
        """Initialize the FrameworkLoader.

        Args:
            backup_manager: Optional BackupManager instance. If None, instantiates a default.
            manager: Optional ExamplesManager instance for cache invalidation and snapshot context.
        """
        self.backup_manager = backup_manager or BackupManager()
        self.manager = manager

    def backup_existing_data(
        self,
        backup_type: str = "snapshot",
        notes: str | None = None,
        folder_name: str | None = None,
        output_dir: str | Path | None = None,
    ) -> dict[str, Any]:
        """Create a backup of existing CISO Assistant data prior to framework operations.

        Args:
            backup_type: 'snapshot' (workspace JSON snapshot, default),
                         'dump' (full database dump via /api/serdes/dump-db/),
                         'framework' (framework answers snapshot), or
                         'none' (skip backup).
            notes: Optional human-readable description for the backup metadata.
            folder_name: Optional folder scope filter for workspace snapshots.
            output_dir: Target directory for backup files.

        Returns:
            Dictionary containing backup metadata, file path, checksum, and status.
        """
        b_type = (backup_type or "snapshot").strip().lower()

        if b_type in ("none", "no", "false", "skip"):
            LOGGER.info("Pre-operation backup explicitly skipped (backup_type='none').")
            return {
                "backup_created": False,
                "backup_type": "none",
                "message": "Backup was skipped by configuration.",
            }

        LOGGER.info(f"Creating pre-load backup of type '{b_type}'...")

        try:
            backup_path: Path | None = None

            if b_type in ("dump", "database", "database_dump"):
                backup_path = self.backup_manager.create_database_dump(output_dir=output_dir)
                if not backup_path or not backup_path.exists():
                    raise RuntimeError("Database dump creation failed or returned empty file.")

            elif b_type in ("framework", "framework_snapshot", "answers"):
                backup_path = self.backup_manager.create_framework_snapshot(
                    output_dir=output_dir,
                    notes=notes or "Pre-load framework answers backup",
                )

            else:
                # Default to workspace JSON snapshot (captures all domains, perimeters, assets, audits, risks, controls)
                data = None
                if self.manager and hasattr(self.manager, "_init_data"):
                    try:
                        data = self.manager._init_data()
                    except Exception as e:
                        LOGGER.warning(f"Could not initialize manager data for workspace snapshot: {e}")

                backup_path = self.backup_manager.create_workspace_snapshot(
                    output_dir=output_dir,
                    folder_name=folder_name or (self.manager.folder_name if self.manager else None),
                    data=data,
                )

            if not backup_path or not Path(backup_path).exists():
                raise RuntimeError(f"Backup creation of type '{b_type}' produced no output file.")

            inspection = self.backup_manager.inspect_backup(backup_path)

            LOGGER.info(
                f"Pre-load backup successfully created: {backup_path.name} "
                f"({inspection.get('size_formatted', 'unknown')}, SHA-256: {inspection.get('sha256', '')[:12]}...)"
            )

            return {
                "backup_created": True,
                "backup_type": b_type,
                "backup_path": str(backup_path),
                "filename": backup_path.name,
                "size_formatted": inspection.get("size_formatted"),
                "size_bytes": inspection.get("size_bytes"),
                "file_size": inspection.get("size_bytes"),
                "checksum": inspection.get("sha256"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status": "success",
            }

        except Exception as e:
            LOGGER.error(f"Failed to create pre-load backup: {e}", exc_info=True)
            raise RuntimeError(f"Pre-load backup failed: {e}") from e

    def list_stored_libraries(
        self,
        query: str | None = None,
        loaded_only: bool = False,
        unloaded_only: bool = False,
    ) -> list[dict[str, Any]]:
        """List stored libraries available in CISO Assistant's built-in catalog.

        Args:
            query: Optional search keyword to filter by name, ref_id, urn, or description.
            loaded_only: If True, only returns libraries currently loaded into frameworks.
            unloaded_only: If True, only returns libraries available to be loaded.

        Returns:
            List of stored library summary dictionaries.
        """
        all_libs = utils.get_all_results("/api/stored-libraries/", force_reload=True)
        results = []

        q_clean = query.strip().lower() if query else None

        for lib in all_libs:
            is_loaded = bool(lib.get("is_loaded"))
            if loaded_only and not is_loaded:
                continue
            if unloaded_only and is_loaded:
                continue

            if q_clean:
                searchable = " ".join([
                    str(lib.get("name") or ""),
                    str(lib.get("ref_id") or ""),
                    str(lib.get("urn") or ""),
                    str(lib.get("description") or ""),
                ]).lower()
                if q_clean not in searchable:
                    continue

            results.append({
                "id": lib.get("id"),
                "ref_id": lib.get("ref_id"),
                "name": lib.get("name"),
                "urn": lib.get("urn"),
                "version": lib.get("version"),
                "locale": lib.get("locale"),
                "is_loaded": is_loaded,
                "builtin": bool(lib.get("builtin")),
                "description": lib.get("description", ""),
            })

        results.sort(key=lambda x: (not x["is_loaded"], x["name"].lower()))
        return results

    def find_stored_library(self, identifier: str) -> dict[str, Any] | None:
        """Find a stored library in CISO Assistant by ID, ref_id, URN, or name.

        Args:
            identifier: UUID, ref_id, URN, or human-readable framework name.

        Returns:
            Raw stored library dictionary, or None if not found.
        """
        if not identifier:
            return None

        target = str(identifier).strip().lower()
        all_libs = utils.get_all_results("/api/stored-libraries/", force_reload=True)

        # 1. Exact ID match
        for lib in all_libs:
            if str(lib.get("id", "")).lower() == target:
                return lib

        # 2. Exact ref_id or URN match
        for lib in all_libs:
            if str(lib.get("ref_id", "")).lower() == target:
                return lib
            if str(lib.get("urn", "")).lower() == target:
                return lib

        # 3. Exact name match
        for lib in all_libs:
            if str(lib.get("name", "")).lower() == target:
                return lib

        # 4. Partial substring match in name or ref_id
        for lib in all_libs:
            if target in str(lib.get("ref_id", "")).lower() or target in str(lib.get("name", "")).lower():
                return lib

        return None

    def get_framework_status(self, identifier: str) -> dict[str, Any]:
        """Inspect the current installation status of a framework in CISO Assistant.

        Args:
            identifier: Framework ref_id, name, URN, or ID.

        Returns:
            Dictionary reporting whether the framework is stored, loaded, its IDs, and versions.
        """
        stored = self.find_stored_library(identifier)
        installed_fws = utils.get_all_results("/api/frameworks/", force_reload=True)

        target = str(identifier).strip().lower()
        matched_fw = None

        for fw in installed_fws:
            if (
                str(fw.get("id", "")).lower() == target
                or str(fw.get("ref_id", "")).lower() == target
                or str(fw.get("name", "")).lower() == target
                or str(fw.get("urn", "")).lower() == target
            ):
                matched_fw = fw
                break

        return {
            "query": identifier,
            "is_stored": stored is not None,
            "stored_id": stored.get("id") if stored else None,
            "stored_version": stored.get("version") if stored else None,
            "is_loaded": matched_fw is not None or (stored and bool(stored.get("is_loaded"))),
            "framework_id": matched_fw.get("id") if matched_fw else None,
            "framework_name": matched_fw.get("name") if matched_fw else (stored.get("name") if stored else None),
            "ref_id": matched_fw.get("ref_id") if matched_fw else (stored.get("ref_id") if stored else None),
            "urn": matched_fw.get("urn") if matched_fw else (stored.get("urn") if stored else None),
        }

    def import_stored_library(
        self,
        identifier: str,
        backup_first: bool = True,
        backup_type: str = "snapshot",
        force_reload: bool = False,
    ) -> dict[str, Any]:
        """Load/import an existing stored library from CISO Assistant's built-in catalog.

        Args:
            identifier: Stored library ID, ref_id, URN, or name.
            backup_first: Whether to automatically backup existing data before loading.
            backup_type: Type of pre-load backup ('snapshot', 'dump', 'framework', or 'none').
            force_reload: If True, unloads the library first if already loaded before re-importing.

        Returns:
            Dictionary with operation status, backup metadata, and framework details.
        """
        stored = self.find_stored_library(identifier)
        if not stored:
            raise ValueError(
                f"Stored library '{identifier}' not found in CISO Assistant catalog. "
                f"Use list_stored_libraries() to browse available libraries."
            )

        lib_id = stored["id"]
        lib_name = stored.get("name", identifier)
        lib_ref = stored.get("ref_id", "")
        lib_urn = stored.get("urn", "")
        is_already_loaded = bool(stored.get("is_loaded"))

        backup_info = {}
        if backup_first:
            backup_info = self.backup_existing_data(
                backup_type=backup_type,
                notes=f"Pre-load backup before importing framework '{lib_name}' ({lib_ref})",
            )

        headers = {
            "Authorization": f"Token {API_TOKEN}",
            "Content-Type": "application/json",
        }

        # If already loaded and force_reload requested, unload first
        if is_already_loaded and force_reload:
            LOGGER.info(f"Framework '{lib_name}' is already loaded. Unloading prior version for reload...")
            unload_url = f"{BASE_URL.rstrip('/')}/api/stored-libraries/{lib_id}/unload/"
            u_res = requests.post(unload_url, headers=headers, verify=False)
            if u_res.status_code not in (200, 204):
                LOGGER.warning(f"Unload returned status {u_res.status_code}: {u_res.text}")

        elif is_already_loaded and not force_reload:
            LOGGER.info(f"Framework '{lib_name}' is already loaded in CISO Assistant.")
            return {
                "success": True,
                "action": "already_loaded",
                "framework_id": stored.get("loaded_library") or lib_id,
                "framework_name": lib_name,
                "ref_id": lib_ref,
                "urn": lib_urn,
                "backup": backup_info,
                "message": f"Framework '{lib_name}' is already loaded in CISO Assistant.",
            }

        # Call the import action on the stored library
        import_url = f"{BASE_URL.rstrip('/')}/api/stored-libraries/{lib_id}/import/"
        LOGGER.info(f"Importing stored library '{lib_name}' via {import_url}...")
        res = requests.post(import_url, headers=headers, verify=False)

        if res.status_code not in (200, 201):
            err_text = res.text
            LOGGER.error(f"Failed to import stored library '{lib_name}' (status {res.status_code}): {err_text}")
            return {
                "success": False,
                "action": "import_failed",
                "error": err_text,
                "status_code": res.status_code,
                "framework_name": lib_name,
                "ref_id": lib_ref,
                "backup": backup_info,
            }

        # Sync caches
        self._sync_cache()

        LOGGER.info(f"Successfully loaded framework '{lib_name}' into CISO Assistant.")
        return {
            "success": True,
            "action": "reloaded" if (is_already_loaded and force_reload) else "imported",
            "framework_id": lib_id,
            "framework_name": lib_name,
            "ref_id": lib_ref,
            "urn": lib_urn,
            "version": stored.get("version"),
            "backup": backup_info,
            "message": f"Successfully loaded framework '{lib_name}' into CISO Assistant.",
        }

    def prepare_framework_payload(
        self,
        file_path: str | Path,
        custom_version: int | None = None,
    ) -> tuple[bytes, str, str, dict[str, Any]]:
        """Read and validate a local framework file and prepare raw bytes and MIME headers for upload.

        Handles:
        - Multi-file includes (!include) in YAML files using utils.load_yaml_file.
        - Special dependencies (e.g., appsec_manual depending on appsec).
        - Excel (.xlsx) framework spreadsheets.

        Args:
            file_path: Path to local YAML or XLSX file.
            custom_version: Optional integer to override the framework version.

        Returns:
            Tuple of (file_bytes, filename, content_type, metadata_dict).
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Framework file not found: {path}")

        filename = path.name
        suffix = path.suffix.lower()

        if suffix == ".xlsx":
            with open(path, "rb") as f:
                content_bytes = f.read()
            return (
                content_bytes,
                filename,
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                {"name": path.stem, "filename": filename, "format": "xlsx"},
            )

        elif suffix in (".yaml", ".yml"):
            data = utils.load_yaml_file(str(path))
            if not isinstance(data, dict):
                raise ValueError(f"Invalid YAML structure in {path}: expected a dictionary root.")

            if custom_version is not None:
                data["version"] = int(custom_version)

            # Special case for appsec_manual: clean duplicate objects and declare dependency
            ref_id = data.get("ref_id", "")
            if ref_id == "appsec_manual" or path.stem == "appsec_manual":
                data["dependencies"] = ["urn:intuitem:risk:library:appsec"]
                if "objects" in data and isinstance(data["objects"], dict) and "framework" in data["objects"]:
                    data["objects"] = {"framework": data["objects"]["framework"]}

            yaml_str = yaml.dump(data, sort_keys=False, allow_unicode=True)
            content_bytes = yaml_str.encode("utf-8")

            metadata = {
                "name": data.get("name", path.stem),
                "ref_id": data.get("ref_id"),
                "urn": data.get("urn"),
                "version": data.get("version", 1),
                "format": "yaml",
                "filename": filename,
            }
            return (content_bytes, filename, "application/yaml", metadata)

        else:
            raise ValueError(f"Unsupported framework file format '{suffix}'. Supported formats: .yaml, .yml, .xlsx.")

    def upload_local_framework(
        self,
        file_path: str | Path,
        backup_first: bool = True,
        backup_type: str = "snapshot",
        force_reload: bool = False,
        custom_version: int | None = None,
    ) -> dict[str, Any]:
        """Upload and load a local framework file (YAML or XLSX) into CISO Assistant.

        Args:
            file_path: Path to the local framework file.
            backup_first: Whether to automatically backup existing data before loading.
            backup_type: Type of pre-load backup ('snapshot', 'dump', 'framework', or 'none').
            force_reload: If True, unloads existing loaded version if present before uploading.
            custom_version: Optional version override.

        Returns:
            Dictionary with operation status, backup metadata, and framework details.
        """
        content_bytes, filename, content_type, metadata = self.prepare_framework_payload(
            file_path, custom_version=custom_version
        )

        fw_name = metadata.get("name", filename)
        fw_ref = metadata.get("ref_id", "")
        fw_urn = metadata.get("urn", "")

        backup_info = {}
        if backup_first:
            backup_info = self.backup_existing_data(
                backup_type=backup_type,
                notes=f"Pre-load backup before uploading framework '{fw_name}' from {filename}",
            )

        # Check if already loaded in CISO Assistant
        existing_status = self.get_framework_status(fw_ref or fw_name or fw_urn)
        if existing_status.get("is_loaded") and force_reload:
            LOGGER.info(f"Framework '{fw_name}' is already loaded. Unloading prior version before upload...")
            if existing_status.get("stored_id"):
                self.unload_framework(existing_status["stored_id"], backup_first=False)

        upload_url = f"{BASE_URL.rstrip('/')}/api/stored-libraries/upload/"
        headers = {
            "Authorization": f"Token {API_TOKEN}",
            "Content-Type": content_type,
            "Content-Disposition": f"attachment; filename={filename}",
        }

        LOGGER.info(f"Uploading framework file {filename} ({len(content_bytes)} bytes) to {upload_url}...")
        res = requests.post(upload_url, data=content_bytes, headers=headers, verify=False)

        if res.status_code not in (200, 201):
            err_msg = res.text
            LOGGER.error(f"Upload failed for {filename} (status {res.status_code}): {err_msg}")
            return {
                "success": False,
                "action": "upload_failed",
                "error": err_msg,
                "status_code": res.status_code,
                "framework_name": fw_name,
                "ref_id": fw_ref,
                "backup": backup_info,
            }

        res_json = {}
        try:
            res_json = res.json()
        except Exception:
            pass

        # Check if library was stored for update (when another version was already loaded)
        warning = res_json.get("warning")
        stored_id = res_json.get("id")

        if warning == "libraryStoredForUpdate" and stored_id:
            LOGGER.info(f"Library stored as update. Triggering import on stored library {stored_id}...")
            # If force_reload or update, unload existing and trigger import
            if force_reload and existing_status.get("stored_id"):
                self.unload_framework(existing_status["stored_id"], backup_first=False)
            import_url = f"{BASE_URL.rstrip('/')}/api/stored-libraries/{stored_id}/import/"
            i_res = requests.post(import_url, headers={"Authorization": f"Token {API_TOKEN}"}, verify=False)
            if i_res.status_code in (200, 201):
                LOGGER.info(f"Successfully imported updated framework {fw_name}.")
            else:
                LOGGER.error(f"Failed to import updated framework {fw_name}: {i_res.text}")
        elif stored_id and not res_json.get("is_loaded"):
            LOGGER.info(f"Library uploaded into catalog. Triggering import on stored library {stored_id}...")
            import_url = f"{BASE_URL.rstrip('/')}/api/stored-libraries/{stored_id}/import/"
            i_res = requests.post(import_url, headers={"Authorization": f"Token {API_TOKEN}"}, verify=False)
            if i_res.status_code in (200, 201):
                LOGGER.info(f"Successfully imported framework {fw_name}.")
            else:
                LOGGER.error(f"Failed to import framework {fw_name}: {i_res.text}")

        # Sync caches
        self._sync_cache()

        LOGGER.info(f"Successfully uploaded and loaded framework '{fw_name}'.")
        return {
            "success": True,
            "action": "uploaded_and_loaded",
            "framework_id": res_json.get("id"),
            "framework_name": res_json.get("name") or fw_name,
            "ref_id": res_json.get("ref_id") or fw_ref,
            "urn": res_json.get("urn") or fw_urn,
            "version": res_json.get("version") or metadata.get("version"),
            "backup": backup_info,
            "message": f"Successfully uploaded and loaded framework '{fw_name}' from {filename}.",
        }

    def unload_framework(
        self,
        identifier: str,
        backup_first: bool = False,
        backup_type: str = "snapshot",
    ) -> dict[str, Any]:
        """Unload an active framework from CISO Assistant.

        Args:
            identifier: Framework ref_id, name, URN, or stored library ID.
            backup_first: Whether to automatically backup existing data before unloading.
            backup_type: Type of pre-unload backup ('snapshot', 'dump', 'framework', or 'none').

        Returns:
            Dictionary reporting unload operation status and backup metadata.
        """
        status = self.get_framework_status(identifier)
        stored_id = status.get("stored_id")
        fw_name = status.get("framework_name", identifier)

        if not stored_id:
            stored = self.find_stored_library(identifier)
            if stored:
                stored_id = stored["id"]
                fw_name = stored.get("name", identifier)

        if not stored_id:
            raise ValueError(f"Could not resolve framework or stored library for '{identifier}'.")

        backup_info = {}
        if backup_first:
            backup_info = self.backup_existing_data(
                backup_type=backup_type,
                notes=f"Pre-unload backup before unloading framework '{fw_name}'",
            )

        headers = {
            "Authorization": f"Token {API_TOKEN}",
            "Content-Type": "application/json",
        }
        unload_url = f"{BASE_URL.rstrip('/')}/api/stored-libraries/{stored_id}/unload/"
        LOGGER.info(f"Unloading framework '{fw_name}' via {unload_url}...")
        res = requests.post(unload_url, headers=headers, verify=False)

        if res.status_code not in (200, 204):
            err_msg = res.text
            LOGGER.error(f"Failed to unload framework '{fw_name}' (status {res.status_code}): {err_msg}")
            return {
                "success": False,
                "action": "unload_failed",
                "error": err_msg,
                "status_code": res.status_code,
                "framework_name": fw_name,
                "backup": backup_info,
            }

        self._sync_cache()
        LOGGER.info(f"Successfully unloaded framework '{fw_name}'.")
        return {
            "success": True,
            "action": "unloaded",
            "framework_name": fw_name,
            "stored_id": stored_id,
            "backup": backup_info,
            "message": f"Successfully unloaded framework '{fw_name}' from CISO Assistant.",
        }

    def load_framework(
        self,
        target: str | Path,
        backup_first: bool = True,
        backup_type: str = "snapshot",
        force_reload: bool = False,
    ) -> dict[str, Any]:
        """Unified framework loader.

        Intelligently detects whether the target is:
        1. A local file path on disk (e.g. 'YML/appsec.yml', custom YAML, or XLSX),
        2. A stored library in CISO Assistant's built-in catalog (by ref_id, URN, name, or UUID),
        3. A local catalog framework short name (e.g. 'appsec', 'appsec_manual').

        In all cases, automatically backs up existing data first (unless backup_first=False).

        Args:
            target: Local file path, stored library identifier, or catalog name.
            backup_first: Whether to automatically backup existing data before loading.
            backup_type: Type of pre-load backup ('snapshot', 'dump', 'framework', or 'none').
            force_reload: If True, forces reload if already loaded.

        Returns:
            Structured operation report dictionary.
        """
        target_str = str(target).strip()

        # 1. Check if target is a direct local file path
        target_path = Path(target_str)
        if target_path.exists() and target_path.is_file():
            LOGGER.info(f"Loading framework from local file '{target_path}'...")
            return self.upload_local_framework(
                target_path,
                backup_first=backup_first,
                backup_type=backup_type,
                force_reload=force_reload,
            )

        # 2. Check if target exists in CISO Assistant stored libraries catalog
        stored = self.find_stored_library(target_str)
        if stored:
            LOGGER.info(f"Loading framework '{stored.get('name')}' from CISO Assistant catalog...")
            return self.import_stored_library(
                stored["id"],
                backup_first=backup_first,
                backup_type=backup_type,
                force_reload=force_reload,
            )

        # 3. Check if target resolves to a local YAML path via ExamplesManager / utils
        resolved_path = None
        if self.manager and hasattr(self.manager, "resolve_framework_yaml_path"):
            try:
                candidate = self.manager.resolve_framework_yaml_path(target_str)
                if candidate and candidate.exists():
                    resolved_path = candidate
            except Exception:
                pass

        if not resolved_path:
            # Check standard YML/ directory candidates
            yml_dir = Path("YML")
            if yml_dir.exists():
                for ext in (".yml", ".yaml"):
                    cand = yml_dir / f"{target_str}{ext}"
                    if cand.exists():
                        resolved_path = cand
                        break

        if resolved_path and resolved_path.exists():
            LOGGER.info(f"Resolved framework '{target_str}' to local file '{resolved_path}'...")
            return self.upload_local_framework(
                resolved_path,
                backup_first=backup_first,
                backup_type=backup_type,
                force_reload=force_reload,
            )

        # Target could not be found anywhere
        available = self.list_stored_libraries()
        sample_names = [f"'{l['ref_id']}' ({l['name'][:30]})" for l in available[:5]]
        raise ValueError(
            f"Could not find framework '{target_str}'. "
            f"It is neither an existing file path nor a recognized catalog/stored library. "
            f"Sample available libraries: {', '.join(sample_names)}."
        )

    def _sync_cache(self) -> None:
        """Invalidate and synchronize local framework caches."""
        if self.manager:
            if hasattr(self.manager, "_init_data"):
                try:
                    self.manager._init_data(force_reload=True)
                except Exception as e:
                    LOGGER.debug(f"Manager cache reload warning: {e}")
        try:
            from ..core.framework import FrameworkDict
            FrameworkDict().reload()
        except Exception:
            pass
