"""NIS2 and ReCyF Domain, Perimeter, and Asset Manager.

Provisions and manages the dedicated organizational domain, perimeters, and assets
representing the target objects on which ReCyF (NIS 2) cybersecurity requirements
are evaluated in CISO Assistant.
"""

import logging
from typing import Any

from .. import utils
from ..organization.asset import AssetDict
from ..organization.domain import DomainDict
from ..organization.perimeter import PerimeterDict

LOGGER = logging.getLogger(__name__)

NIS2_DOMAIN_NAME = "NIS2 - ReCyF"
NIS2_DOMAIN_DESCRIPTION = (
    "Domaine dédié au pilotage de la conformité NIS 2 et à l'évaluation du Référentiel Cyber France (ANSSI ReCyF v2.5)."
)

# 10 Dedicated Perimeters and Assets mapped to ReCyF's 20 Security Objectives
RECYF_ASSET_DEFINITIONS = [
    {
        "id": "governance_organization",
        "name": "Gouvernance, Organisation & RH",
        "type": "PR",
        "perimeter_name": "Périmètre Gouvernance, Risques & Conformité NIS 2",
        "description": (
            "Gouvernance globale de la sécurité numérique, PSSI, responsabilités du dirigeant et RSSI, "
            "gestion des risques, gestion de crise cyber, exercices, audits et sécurité RH (Obj 1.1, 2, 4, 14, 15, 16, 17)."
        ),
        "objectives": ["1.1", "2.A", "2.B", "2.C", "4", "14", "15", "16", "17"],
        "req_count": 40,
    },
    {
        "id": "information_systems",
        "name": "Systèmes d'Information & Applications Métier",
        "type": "PR",
        "perimeter_name": "Périmètre Systèmes d'Information et Applications NIS 2",
        "description": (
            "Applications et systèmes d'information supports, gestion du cycle de vie, maintien en conditions "
            "opérationnelles et de sécurité (MCO/MCS), gestion des vulnérabilités, correctifs et PCA/PRA (Obj 1.2-1.3, 5, 13)."
        ),
        "objectives": ["1.2", "1.3", "5.A", "5.B", "13"],
        "req_count": 19,
    },
    {
        "id": "ecosystem_suppliers",
        "name": "Écosystème & Fournisseurs Tiers",
        "type": "PR",
        "perimeter_name": "Périmètre Écosystème et Fournisseurs Tiers NIS 2",
        "description": (
            "Cartographie de l'écosystème tiers, prestataires informatiques, sous-traitants, clauses contractuelles "
            "de cybersécurité, plans d'assurance sécurité (PAS), notifications d'incidents et audits tiers (Obj 3)."
        ),
        "objectives": ["3.A", "3.B"],
        "req_count": 4,
    },
    {
        "id": "network_architecture",
        "name": "Architecture Réseau & Accès Distants",
        "type": "SP",
        "perimeter_name": "Périmètre Architecture Réseau et Accès Distants NIS 2",
        "description": (
            "Architecture réseau, cloisonnement (inter-SI et sous-systèmes), passerelles sécurisées (DMZ, proxy sortant), "
            "filtrage pare-feu (déni par défaut) et accès distants sécurisés via VPN chiffré et MFA (Obj 7, 8.1-8.4)."
        ),
        "objectives": ["7.A", "7.B", "8.1-8.4"],
        "req_count": 17,
    },
    {
        "id": "endpoints",
        "name": "Postes de Travail & Terminaux Nomades",
        "type": "SP",
        "perimeter_name": "Périmètre Postes de Travail et Terminaux Nomades NIS 2",
        "description": (
            "Parc de postes utilisateurs, ordinateurs portables, terminaux nomades, chiffrement des disques durs, "
            "protection antivirale / EDR, restriction matérielle et blocage des supports amovibles USB (Obj 8.5, 9)."
        ),
        "objectives": ["8.5", "9"],
        "req_count": 8,
    },
    {
        "id": "iam_directories",
        "name": "Identités, Accès & Annuaires (IAM / AD)",
        "type": "SP",
        "perimeter_name": "Périmètre Identités, Accès et Annuaires (IAM) NIS 2",
        "description": (
            "Gestion du cycle de vie des identités, comptes individuels, politique de mots de passe, MFA, moindre privilège, "
            "contrôleurs de domaine et annuaires d'entreprise constituant le cœur de confiance (Obj 10, 11.B)."
        ),
        "objectives": ["10.A", "10.B", "10.C", "11.B"],
        "req_count": 24,
    },
    {
        "id": "administration_pav",
        "name": "Ressources d'Administration Dédiées (PAV)",
        "type": "SP",
        "perimeter_name": "Périmètre Administration et Postes Dédiés (PAV) NIS 2",
        "description": (
            "Comptes d'administration à privilèges élevés, séparation des tâches, réseau d'administration dédié hors-bande, "
            "postes physiques d'administration dédiés (PAV) et chiffrement de bout en bout des flux d'admin (Obj 11.A, 19)."
        ),
        "objectives": ["11.A", "19"],
        "req_count": 19,
    },
    {
        "id": "infrastructure_servers",
        "name": "Serveurs & Équipements d'Infrastructure",
        "type": "SP",
        "perimeter_name": "Périmètre Serveurs et Équipements d'Infrastructure NIS 2",
        "description": (
            "Serveurs physiques et virtuels, appliances d'infrastructure, durcissement (hardening), suppression des services "
            "inutiles, guides de configuration sécurisée et revues de conformité (Obj 18)."
        ),
        "objectives": ["18"],
        "req_count": 4,
    },
    {
        "id": "supervision_soc",
        "name": "Supervision, Logs & Détection (SOC / SIEM)",
        "type": "SP",
        "perimeter_name": "Périmètre Supervision, Logs et Détection (SOC) NIS 2",
        "description": (
            "Détection des incidents de sécurité, qualification, notification ANSSI, scellement des preuves numériques, "
            "centralisation des journaux (logs), horodatage NTP et immuabilité des traces d'audit (Obj 12, 20)."
        ),
        "objectives": ["12", "20"],
        "req_count": 13,
    },
    {
        "id": "physical_security",
        "name": "Locaux Physiques & Salles Serveurs",
        "type": "SP",
        "perimeter_name": "Périmètre Locaux Techniques et Datacenters NIS 2",
        "description": (
            "Sécurité physique des bâtiments, locaux techniques, salles serveurs, baies informatiques, contrôle d'accès "
            "physique (badges, sas), habilitations et accompagnement systématique des intervenants extérieurs (Obj 6)."
        ),
        "objectives": ["6"],
        "req_count": 4,
    },
]


class ReCyFDomainManager:
    """Manages the creation and inspection of the NIS2 / ReCyF organizational domain, perimeters, and assets."""

    def __init__(self, domain_name: str = NIS2_DOMAIN_NAME):
        self.domain_name = domain_name

    def provision_nis2_recyf_environment(self, assignee_id: str | None = None) -> dict[str, Any]:
        """Create the NIS2 - ReCyF domain, perimeters, and corresponding assets in CISO Assistant."""
        utils.log(f"Starting provisioning for NIS2 ReCyF domain: '{self.domain_name}'...", level=logging.INFO)

        # 1. Initialize collections
        domain_dict = DomainDict()
        perimeter_dict = PerimeterDict()
        asset_dict = AssetDict()

        # 2. Create or retrieve domain/folder
        folder_id = domain_dict.get_id_from_name(self.domain_name)
        if not folder_id:
            domain_res = domain_dict.create_domain(
                name=self.domain_name,
                description=NIS2_DOMAIN_DESCRIPTION,
                create_iam_groups=True,
            )
            domain_dict.reload()
            folder_id = domain_dict.get_id_from_name(self.domain_name)
            if not folder_id and isinstance(domain_res, dict):
                folder_id = domain_res.get("id")

        if not folder_id:
            raise RuntimeError(f"Failed to create or retrieve domain '{self.domain_name}'")

        utils.log(f"Using domain '{self.domain_name}' (ID: {folder_id})", level=logging.INFO)

        # 3. Create perimeters and assets
        created_perimeters = []
        created_assets = []

        for item in RECYF_ASSET_DEFINITIONS:
            p_name = item["perimeter_name"]
            a_name = item["name"]
            a_type = item["type"]
            a_desc = item["description"]

            # Create Perimeter
            existing_p = perimeter_dict.get_id_from_name(p_name)
            if not existing_p:
                utils.log(f"Creating perimeter: '{p_name}'", level=logging.INFO)
                payload_p = {"name": p_name, "folder": folder_id}
                p_res = utils.get_return("/api/perimeters/", method="POST", payload=payload_p)
                perimeter_dict.reload()
                p_id = perimeter_dict.get_id_from_name(p_name)
                if not p_id and isinstance(p_res, dict):
                    p_id = p_res.get("id")
            else:
                p_id = existing_p
                utils.log(f"Perimeter already exists: '{p_name}' (ID: {p_id})")

            created_perimeters.append({"name": p_name, "id": p_id})

            # Create Asset
            existing_a = asset_dict.get_asset_id_from_perimeter_name(a_name)
            if not existing_a:
                utils.log(f"Creating asset: '{a_name}' (type: {a_type})", level=logging.INFO)
                payload_a = {
                    "name": a_name,
                    "type": a_type,
                    "folder": folder_id,
                    "description": a_desc,
                }
                a_res = utils.get_return("/api/assets/", method="POST", payload=payload_a)
                asset_dict.reload()
                a_id = asset_dict.get_asset_id_from_perimeter_name(a_name)
                if not a_id and isinstance(a_res, dict):
                    a_id = a_res.get("id")
            else:
                a_id = existing_a
                utils.log(f"Asset already exists: '{a_name}' (ID: {a_id})")

            created_assets.append({
                "name": a_name,
                "id": a_id,
                "type": a_type,
                "perimeter_name": p_name,
                "perimeter_id": p_id,
                "description": a_desc,
                "req_count": item["req_count"],
            })

        return {
            "domain_name": self.domain_name,
            "domain_id": folder_id,
            "perimeters": created_perimeters,
            "assets": created_assets,
            "total_assets": len(created_assets),
        }

    def get_nis2_recyf_status(self) -> dict[str, Any]:
        """Check whether the NIS2 ReCyF domain, perimeters, and assets exist."""
        domain_dict = DomainDict()
        perimeter_dict = PerimeterDict()
        asset_dict = AssetDict()

        folder_id = domain_dict.get_id_from_name(self.domain_name)
        if not folder_id:
            return {"exists": False, "domain_name": self.domain_name}

        status_items = []
        for item in RECYF_ASSET_DEFINITIONS:
            p_id = perimeter_dict.get_id_from_name(item["perimeter_name"])
            a_id = asset_dict.get_asset_id_from_perimeter_name(item["name"])
            status_items.append({
                "name": item["name"],
                "type": item["type"],
                "perimeter_name": item["perimeter_name"],
                "perimeter_id": p_id,
                "asset_id": a_id,
                "perimeter_exists": bool(p_id),
                "asset_exists": bool(a_id),
                "req_count": item["req_count"],
                "objectives": item["objectives"],
            })

        return {
            "exists": True,
            "domain_name": self.domain_name,
            "domain_id": folder_id,
            "items": status_items,
        }
