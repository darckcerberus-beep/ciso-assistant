"""Unit tests for Findings Assessment, Finding models, and audit findings generation."""

import unittest
from unittest.mock import MagicMock, patch

from classes.audits.compliance import ComplianceAssessment, ComplianceAssessmentDict
from classes.audits.finding import Finding, FindingDict, FindingsAssessment, FindingsAssessmentDict
from classes.core.risk import ThreatDict, VulnerabilityDict
from classes.examples_manager import ExamplesManager


class TestFindingModels(unittest.TestCase):
    """Test suite for FindingsAssessment and Finding data classes."""

    def test_findings_assessment_model(self):
        """Verify FindingsAssessment getters from API payload."""
        sample_json = {
            "id": "fa-uuid-1",
            "name": "App-Secure-Core Findings",
            "folder": {"id": "folder-uuid-1", "name": "Folder 1"},
            "perimeter": {"id": "perm-uuid-1", "name": "App-Secure-Core"},
            "category": "audit",
            "status": "in_progress",
            "findings_count": 3,
        }
        fa = FindingsAssessment(sample_json)
        self.assertEqual(fa.get_id(), "fa-uuid-1")
        self.assertEqual(fa.get_name(), "App-Secure-Core Findings")
        self.assertEqual(fa.get_folder_id(), "folder-uuid-1")
        self.assertEqual(fa.get_perimeter_id(), "perm-uuid-1")
        self.assertEqual(fa.get_category(), "audit")
        self.assertEqual(fa.get_status(), "in_progress")
        self.assertEqual(fa.get_findings_count(), 3)
        self.assertEqual(fa.get_json(), sample_json)

    def test_finding_model(self):
        """Verify Finding getters from API payload."""
        sample_json = {
            "id": "f-uuid-1",
            "name": "Audit Finding: Non-compliance on Data Encryption",
            "findings_assessment": "fa-uuid-1",
            "severity": 4,
            "priority": 1,
            "status": "identified",
            "requirement_node": {"id": "rn-uuid-1"},
            "asset": {"id": "asset-uuid-1"},
        }
        f = Finding(sample_json)
        self.assertEqual(f.get_id(), "f-uuid-1")
        self.assertEqual(f.get_name(), "Audit Finding: Non-compliance on Data Encryption")
        self.assertEqual(f.get_findings_assessment_id(), "fa-uuid-1")
        self.assertEqual(f.get_severity(), 4)
        self.assertEqual(f.get_priority(), 1)
        self.assertEqual(f.get_status(), "identified")
        self.assertEqual(f.get_requirement_node_id(), "rn-uuid-1")
        self.assertEqual(f.get_asset_id(), "asset-uuid-1")
        self.assertEqual(f.get_json(), sample_json)


class TestFindingDicts(unittest.TestCase):
    """Test suite for FindingsAssessmentDict and FindingDict collections."""

    @patch("classes.utils.get_all_results")
    def test_findings_assessment_dict_reload_and_get(self, mock_get_all):
        """Verify reloading and retrieving findings assessments."""
        mock_get_all.return_value = [
            {"id": "fa-1", "name": "Assessment 1", "category": "audit"},
            {"id": "fa-2", "name": "Assessment 2", "category": "pentest"},
        ]
        fa_dict = FindingsAssessmentDict()
        self.assertEqual(len(fa_dict.get_findings_assessments()), 2)
        self.assertEqual(fa_dict.get_id_from_name("Assessment 1"), "fa-1")
        self.assertEqual(fa_dict.get_id_from_name("Assessment 2"), "fa-2")
        self.assertIsNone(fa_dict.get_id_from_name("NonExistent"))

    @patch("classes.utils.get_return")
    @patch("classes.utils.get_all_results")
    def test_findings_assessment_dict_create_and_patch(self, mock_get_all, mock_get_return):
        """Verify idempotent create (POST) and update (PATCH) of findings assessments."""
        mock_get_all.return_value = []
        fa_dict = FindingsAssessmentDict()

        # 1. Create new via POST
        mock_get_return.return_value = {"id": "fa-new", "name": "New Audit", "category": "audit"}
        created = fa_dict.create_findings_assessment(
            name="New Audit",
            folder_id="folder-1",
            perimeter_id="perm-1",
        )
        self.assertEqual(created["id"], "fa-new")
        self.assertIn("fa-new", fa_dict.get_findings_assessments())
        mock_get_return.assert_called_with(
            "/api/findings-assessments/",
            method="POST",
            payload={
                "name": "New Audit",
                "category": "audit",
                "status": "in_progress",
                "folder": "folder-1",
                "perimeter": "perm-1",
            },
        )

        # 2. Update existing via PATCH
        mock_get_return.return_value = {"id": "fa-new", "name": "New Audit", "status": "done"}
        updated = fa_dict.create_findings_assessment(
            name="New Audit",
            folder_id="folder-1",
            status="done",
        )
        self.assertEqual(updated["status"], "done")
        call_args = mock_get_return.call_args
        self.assertEqual(call_args[0][0], "/api/findings-assessments/fa-new/")
        self.assertEqual(call_args[1]["method"], "PATCH")

    @patch("classes.utils.get_return")
    @patch("classes.utils.get_all_results")
    def test_findings_assessment_dict_delete(self, mock_get_all, mock_get_return):
        """Verify deletion of a findings assessment."""
        mock_get_all.return_value = [{"id": "fa-del", "name": "To Delete"}]
        fa_dict = FindingsAssessmentDict()
        self.assertIn("fa-del", fa_dict.get_findings_assessments())

        mock_get_return.return_value = True
        success = fa_dict.delete_findings_assessment("fa-del")
        self.assertTrue(success)
        self.assertNotIn("fa-del", fa_dict.get_findings_assessments())
        mock_get_return.assert_called_once_with("/api/findings-assessments/fa-del/", method="DELETE")

    @patch("classes.utils.get_all_results")
    def test_finding_dict_reload_and_get_for_assessment(self, mock_get_all):
        """Verify filtering findings by findings_assessment UUID."""
        mock_get_all.return_value = [
            {"id": "f-1", "name": "Finding 1", "findings_assessment": "fa-1"},
            {"id": "f-2", "name": "Finding 2", "findings_assessment": "fa-1"},
            {"id": "f-3", "name": "Finding 3", "findings_assessment": "fa-2"},
        ]
        f_dict = FindingDict()
        self.assertEqual(len(f_dict.get_findings()), 3)
        fa1_findings = f_dict.get_findings_for_assessment("fa-1")
        self.assertEqual(len(fa1_findings), 2)
        self.assertEqual([f.get_id() for f in fa1_findings], ["f-1", "f-2"])

    @patch("classes.utils.get_return")
    @patch("classes.utils.get_all_results")
    def test_finding_dict_create_and_patch(self, mock_get_all, mock_get_return):
        """Verify idempotent create (POST) and update (PATCH) of findings."""
        mock_get_all.return_value = []
        f_dict = FindingDict()

        # 1. Create via POST
        mock_get_return.return_value = {
            "id": "f-new",
            "name": "Weak Passwords",
            "findings_assessment": "fa-1",
            "severity": 3,
            "priority": 2,
        }
        created = f_dict.create_finding(
            findings_assessment_id="fa-1",
            name="Weak Passwords",
            severity=3,
            priority=2,
        )
        self.assertEqual(created["id"], "f-new")
        self.assertIn("f-new", f_dict.get_findings())

        # 2. Update via PATCH
        mock_get_return.return_value = {
            "id": "f-new",
            "name": "Weak Passwords",
            "findings_assessment": "fa-1",
            "severity": 4,
            "priority": 1,
        }
        updated = f_dict.create_finding(
            findings_assessment_id="fa-1",
            name="Weak Passwords",
            severity=4,
            priority=1,
        )
        self.assertEqual(updated["severity"], 4)
        call_args = mock_get_return.call_args
        self.assertEqual(call_args[0][0], "/api/findings/f-new/")
        self.assertEqual(call_args[1]["method"], "PATCH")

    @patch("classes.utils.get_return")
    @patch("classes.utils.get_all_results")
    def test_finding_dict_delete_and_delete_for_assessment(self, mock_get_all, mock_get_return):
        """Verify individual deletion and cascading deletion for a findings assessment."""
        mock_get_all.return_value = [
            {"id": "f-1", "name": "Finding 1", "findings_assessment": "fa-1"},
            {"id": "f-2", "name": "Finding 2", "findings_assessment": "fa-1"},
            {"id": "f-3", "name": "Finding 3", "findings_assessment": "fa-2"},
        ]
        f_dict = FindingDict()
        mock_get_return.return_value = True

        # Delete all findings for fa-1
        del_count = f_dict.delete_findings_for_assessment("fa-1")
        self.assertEqual(del_count, 2)
        self.assertEqual(len(f_dict.get_findings()), 1)
        self.assertIn("f-3", f_dict.get_findings())


class TestFindingsGenerationFromAuditAnswers(unittest.TestCase):
    """Test suite for mapping compliance assessment answers to findings."""

    @patch("classes.utils.get_all_results", return_value=[])
    def test_compliant_answers_generate_zero_findings(self, _):
        """Verify that 100% compliant answers generate 0 findings."""
        compliance_dict = ComplianceAssessmentDict()
        mock_ca = MagicMock()
        mock_ca.get_id.return_value = "ca-1"
        mock_ca.get_name.return_value = "App-Secure-Core Assessment"
        mock_ca.get_perimeter_id.return_value = "perm-1"
        mock_ca.get_asset_id_list.return_value = ["asset-1"]
        mock_ca.get_json.return_value = {"folder": "folder-1"}
        compliance_dict.compliance_assessments = {"ca-1": mock_ca}

        # Mock requirement assessments: all compliant
        mock_ra1 = MagicMock()
        mock_ra1.get_compliance_assessment_id.return_value = "ca-1"
        mock_ra1.has_selected_answer.return_value = True
        mock_ra1.is_unassessed_result.return_value = False
        mock_ra1.get_assessment_results.return_value = "compliant"
        mock_ra1.get_score.return_value = "100.0"

        mock_ra_dict = MagicMock()
        mock_ra_dict.has_answers_for_compliance_assessment.return_value = True
        mock_ra_dict.get_requirement_assessments.return_value = {"ra-1": mock_ra1}

        mock_fa_dict = MagicMock()
        mock_fa_dict.create_findings_assessment.return_value = {"id": "fa-1"}
        mock_f_dict = MagicMock()

        summaries = compliance_dict.create_findings_assessments(
            findings_assessment_dict=mock_fa_dict,
            finding_dict=mock_f_dict,
            requirement_assessment_dict=mock_ra_dict,
        )

        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0]["findings_count"], 0)
        mock_f_dict.create_finding.assert_not_called()

    @patch("classes.utils.get_all_results", return_value=[])
    def test_non_compliant_answers_generate_critical_or_high_findings(self, _):
        """Verify non-compliant answers on high sensitivity asset generate Severity 4 (Critical) and Priority 1."""
        compliance_dict = ComplianceAssessmentDict()
        mock_ca = MagicMock()
        mock_ca.get_id.return_value = "ca-2"
        mock_ca.get_name.return_value = "App-Vulnerable-Portal Assessment"
        mock_ca.get_perimeter_id.return_value = "perm-2"
        mock_ca.get_asset_id_list.return_value = ["asset-2"]
        mock_ca.get_json.return_value = {"folder": "folder-2"}
        compliance_dict.compliance_assessments = {"ca-2": mock_ca}

        # Requirement assessment: non_compliant (score 0.0)
        mock_ra = MagicMock()
        mock_ra.get_compliance_assessment_id.return_value = "ca-2"
        mock_ra.has_selected_answer.return_value = True
        mock_ra.is_unassessed_result.return_value = False
        mock_ra.get_assessment_results.return_value = "non_compliant"
        mock_ra.get_score.return_value = "0.0"
        mock_ra.get_name.return_value = "Data in Transit Encryption"
        mock_ra.get_urn.return_value = "urn:dpp:transit_encryption"
        mock_ra.get_requirement_ref_id.return_value = "ENC-01"
        mock_ra.get_asset_id_list.return_value = ["asset-2"]
        mock_ra.get_requirement_json.return_value = {
            "requirement": {"id": "req-node-1", "name": "Data in Transit Encryption", "description": "Must encrypt."},
            "observation": "No SSL/TLS enabled",
        }
        mock_ra.get_associated_reference_control_ids.return_value = ["rc-1"]
        mock_ra.get_applied_control_ids.return_value = ["ctrl-1"]

        mock_ra_dict = MagicMock()
        mock_ra_dict.has_answers_for_compliance_assessment.return_value = True
        mock_ra_dict.get_requirement_assessments.return_value = {"ra-2": mock_ra}

        # Asset is Secret / Critical
        mock_asset = MagicMock()
        mock_asset.get_id.return_value = "asset-2"
        mock_asset.get_security_objectives.return_value = {"confidentiality": 4}
        mock_asset_dict = MagicMock()
        mock_asset_dict.get_assets.return_value = [mock_asset]
        mock_asset_dict.get_owner_ids_for_assets.return_value = ["owner-uuid"]

        # Framework file with threat/vuln mappings
        mock_fw_file = MagicMock()
        mock_fw_file.json_object = {
            "objects": {
                "vulnerabilities": [{"urn": "urn:vuln:cleartext", "threats": ["urn:threat:sniffing"]}],
                "framework": {
                    "requirement_nodes": [
                        {"urn": "urn:dpp:transit_encryption", "vulnerabilities": ["urn:vuln:cleartext"]}
                    ]
                },
            }
        }

        mock_vuln_dict = MagicMock()
        mock_vuln_dict.get_id_by_urn.return_value = "vid-cleartext"
        mock_vuln_dict.get_vulnerability_id_for_asset.return_value = "vid-cleartext"
        mock_threat_dict = MagicMock()
        mock_threat_dict.get_id_by_urn.return_value = "tid-sniffing"

        mock_fa_dict = MagicMock()
        mock_fa_dict.create_findings_assessment.return_value = {"id": "fa-2"}
        mock_f_dict = MagicMock()
        mock_f_dict.create_finding.return_value = {"id": "f-2"}

        summaries = compliance_dict.create_findings_assessments(
            findings_assessment_dict=mock_fa_dict,
            finding_dict=mock_f_dict,
            requirement_assessment_dict=mock_ra_dict,
            asset_dict=mock_asset_dict,
            vulnerability_dict=mock_vuln_dict,
            threat_dict=mock_threat_dict,
            framework_file=mock_fw_file,
        )

        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0]["findings_count"], 1)

        # Verify Finding properties
        mock_f_dict.create_finding.assert_called_once()
        call_kwargs = mock_f_dict.create_finding.call_args[1]
        self.assertEqual(call_kwargs["findings_assessment_id"], "fa-2")
        self.assertIn("Data in Transit Encryption", call_kwargs["name"])
        self.assertEqual(call_kwargs["severity"], 4)  # Critical due to confidentiality=4
        self.assertEqual(call_kwargs["priority"], 1)  # P1
        self.assertEqual(call_kwargs["status"], "identified")
        self.assertEqual(call_kwargs["asset"], "asset-2")
        self.assertEqual(call_kwargs["vulnerabilities"], ["vid-cleartext"])
        self.assertEqual(call_kwargs["threats"], ["tid-sniffing"])
        self.assertEqual(call_kwargs["reference_controls"], ["rc-1"])
        self.assertEqual(call_kwargs["applied_controls"], ["ctrl-1"])
        self.assertEqual(call_kwargs["owner"], ["owner-uuid"])

    @patch("classes.utils.get_all_results", return_value=[])
    def test_partially_compliant_answers_generate_medium_findings(self, _):
        """Verify partially compliant answers (score 50%) generate Severity 2 (Medium) and Priority 3 (P3)."""
        compliance_dict = ComplianceAssessmentDict()
        mock_ca = MagicMock()
        mock_ca.get_id.return_value = "ca-3"
        mock_ca.get_name.return_value = "App-Internal-Tool Assessment"
        mock_ca.get_perimeter_id.return_value = "perm-3"
        mock_ca.get_asset_id_list.return_value = ["asset-3"]
        mock_ca.get_json.return_value = {"folder": "folder-3"}
        compliance_dict.compliance_assessments = {"ca-3": mock_ca}

        mock_ra = MagicMock()
        mock_ra.get_compliance_assessment_id.return_value = "ca-3"
        mock_ra.has_selected_answer.return_value = True
        mock_ra.is_unassessed_result.return_value = False
        mock_ra.get_assessment_results.return_value = "partially_compliant"
        mock_ra.get_score.return_value = "50.0"
        mock_ra.get_name.return_value = "Access Management"
        mock_ra.get_urn.return_value = "urn:dpp:access_mgmt"
        mock_ra.get_requirement_ref_id.return_value = "ACC-01"
        mock_ra.get_asset_id_list.return_value = ["asset-3"]
        mock_ra.get_requirement_json.return_value = {
            "requirement": {"id": "req-node-3", "name": "Access Management"},
            "observation": "MFA is partial",
        }
        mock_ra.get_associated_reference_control_ids.return_value = []
        mock_ra.get_applied_control_ids.return_value = []

        mock_ra_dict = MagicMock()
        mock_ra_dict.has_answers_for_compliance_assessment.return_value = True
        mock_ra_dict.get_requirement_assessments.return_value = {"ra-3": mock_ra}

        mock_fa_dict = MagicMock()
        mock_fa_dict.create_findings_assessment.return_value = {"id": "fa-3"}
        mock_f_dict = MagicMock()
        mock_f_dict.create_finding.return_value = {"id": "f-3"}

        summaries = compliance_dict.create_findings_assessments(
            findings_assessment_dict=mock_fa_dict,
            finding_dict=mock_f_dict,
            requirement_assessment_dict=mock_ra_dict,
        )

        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0]["findings_count"], 1)

        call_kwargs = mock_f_dict.create_finding.call_args[1]
        self.assertEqual(call_kwargs["severity"], 2)  # Medium
        self.assertEqual(call_kwargs["priority"], 3)  # P3

    @patch("classes.utils.get_all_results", return_value=[])
    def test_not_applicable_answers_ignored(self, _):
        """Verify that not_applicable answers do not generate findings."""
        compliance_dict = ComplianceAssessmentDict()
        mock_ca = MagicMock()
        mock_ca.get_id.return_value = "ca-4"
        mock_ca.get_name.return_value = "App-Public-Blog Assessment"
        mock_ca.get_perimeter_id.return_value = "perm-4"
        mock_ca.get_asset_id_list.return_value = []
        mock_ca.get_json.return_value = {"folder": "folder-4"}
        compliance_dict.compliance_assessments = {"ca-4": mock_ca}

        mock_ra = MagicMock()
        mock_ra.get_compliance_assessment_id.return_value = "ca-4"
        mock_ra.has_selected_answer.return_value = True
        mock_ra.is_unassessed_result.return_value = False
        mock_ra.get_assessment_results.return_value = "not_applicable"
        mock_ra.get_score.return_value = None

        mock_ra_dict = MagicMock()
        mock_ra_dict.has_answers_for_compliance_assessment.return_value = True
        mock_ra_dict.get_requirement_assessments.return_value = {"ra-4": mock_ra}

        mock_fa_dict = MagicMock()
        mock_fa_dict.create_findings_assessment.return_value = {"id": "fa-4"}
        mock_f_dict = MagicMock()

        summaries = compliance_dict.create_findings_assessments(
            findings_assessment_dict=mock_fa_dict,
            finding_dict=mock_f_dict,
            requirement_assessment_dict=mock_ra_dict,
        )

        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0]["findings_count"], 0)
        mock_f_dict.create_finding.assert_not_called()


class TestExamplesManagerFindingsIntegration(unittest.TestCase):
    """Test suite for ExamplesManager findings creation workflow."""

    def setUp(self):
        self.manager = ExamplesManager()

    def test_create_findings_for_application_internal(self):
        """Verify create_findings_for_application resolves internal application and delegates to compliance_dict."""
        mock_data = {
            "perimeter_dict": MagicMock(),
            "compliance_assessment_dict": MagicMock(),
            "findings_assessment_dict": MagicMock(),
            "finding_dict": MagicMock(),
            "asset_dict": MagicMock(),
            "vulnerability_dict": MagicMock(),
            "threat_dict": MagicMock(),
            "framework_file": MagicMock(),
        }

        mock_data["perimeter_dict"].get_id_from_name.return_value = "perm-portal"

        mock_ca = MagicMock()
        mock_ca.get_id.return_value = "ca-portal"
        mock_ca.get_name.return_value = "Assessment of Multi-level DPP in App-Vulnerable-Portal"
        mock_ca.get_perimeter_id.return_value = "perm-portal"
        mock_data["compliance_assessment_dict"].get_compliance_assessments.return_value = {"ca-portal": mock_ca}

        mock_data["compliance_assessment_dict"].create_findings_assessments.return_value = [
            {
                "compliance_assessment_id": "ca-portal",
                "findings_assessment_id": "fa-portal",
                "findings_assessment_name": "Assessment of Multi-level DPP in App-Vulnerable-Portal Findings",
                "findings_count": 5,
            }
        ]

        self.manager.data = mock_data
        with patch.object(self.manager, "_init_data", return_value=mock_data):
            res = self.manager.create_findings_for_application("app_vulnerable_portal")
            self.assertEqual(res["app_name"], "App-Vulnerable-Portal")
            self.assertEqual(res["findings_assessment_id"], "fa-portal")
            self.assertEqual(res["findings_count"], 5)

            mock_data["compliance_assessment_dict"].create_findings_assessments.assert_called_once_with(
                findings_assessment_dict=mock_data["findings_assessment_dict"],
                finding_dict=mock_data["finding_dict"],
                requirement_assessment_dict=mock_data["compliance_assessment_dict"].requirement_assessments,
                asset_dict=mock_data["asset_dict"],
                vulnerability_dict=mock_data["vulnerability_dict"],
                threat_dict=mock_data["threat_dict"],
                framework_file=mock_data["framework_file"],
                compliance_assessment_id="ca-portal",
            )

    def test_create_findings_for_application_tprm(self):
        """Verify create_findings_for_application resolves TPRM application via entity_assessment."""
        mock_data = {
            "perimeter_dict": MagicMock(),
            "entity_dict": MagicMock(),
            "entity_assessment_dict": MagicMock(),
            "compliance_assessment_dict": MagicMock(),
            "findings_assessment_dict": MagicMock(),
            "finding_dict": MagicMock(),
            "asset_dict": MagicMock(),
            "vulnerability_dict": MagicMock(),
            "threat_dict": MagicMock(),
            "framework_file": MagicMock(),
        }

        mock_data["perimeter_dict"].get_id_from_name.return_value = None  # Not an internal perimeter
        mock_data["entity_dict"].get_id_from_name.return_value = "entity-tprm"

        mock_ea = MagicMock()
        mock_ea.get_entity_id.return_value = "entity-tprm"
        mock_ea.get_compliance_assessment_id.return_value = "ca-tprm"
        mock_data["entity_assessment_dict"].get_entity_assessments.return_value = [mock_ea]

        mock_ca = MagicMock()
        mock_ca.get_id.return_value = "ca-tprm"
        mock_ca.get_name.return_value = "Third-Party Assessment for Vendor X"
        mock_ca.get_perimeter_id.return_value = None
        mock_data["compliance_assessment_dict"].get_compliance_assessments.return_value = {"ca-tprm": mock_ca}

        mock_data["compliance_assessment_dict"].create_findings_assessments.return_value = [
            {
                "compliance_assessment_id": "ca-tprm",
                "findings_assessment_id": "fa-tprm",
                "findings_assessment_name": "Third-Party Assessment for Vendor X Findings",
                "findings_count": 3,
            }
        ]

        self.manager.data = mock_data
        with patch.object(self.manager, "_init_data", return_value=mock_data):
            res = self.manager.create_findings_for_application("App-AI-Analytics-Workbench")
            self.assertEqual(res["findings_assessment_id"], "fa-tprm")
            self.assertEqual(res["findings_count"], 3)


if __name__ == "__main__":
    unittest.main()
