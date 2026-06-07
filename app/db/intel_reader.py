"""
Interface de lecture de la base Threat Intel locale (data/threat_intel.db).
Utilisée par le pipeline RAG et le ReportValidator pour récupérer des données
CVE vérifiées sans effectuer de requête réseau.
"""
import json
import logging
from pathlib import Path

from packaging.version import InvalidVersion, Version

from app.db.threat_intel_db import IntelCVE, get_intel_session

logger = logging.getLogger(__name__)

NO_CVE_CONFIRMED = (
    "⚠ Aucune CVE confirmée dans la base locale SIATI pour ce service/version.\n"
    "Pour mettre à jour : cd siati_intel_builder && python main.py"
)


class IntelReader:
    """Accès en lecture seule à threat_intel.db."""

    def get_cve(self, cve_id: str) -> dict | None:
        """Retourne l'entrée CVE complète ou None si absente de la base."""
        session = get_intel_session()
        if session is None:
            logger.warning("threat_intel.db absent — base intel non disponible.")
            return None
        try:
            row = session.query(IntelCVE).filter_by(cve_id=cve_id).first()
            if not row:
                return None
            return self._row_to_dict(row)
        finally:
            session.close()

    def get_cves_for_service(self, service_name: str, version: str) -> list[dict]:
        """
        Retourne uniquement les CVE dont affected_versions contient
        explicitement la version cible. Aucune inférence, aucune approximation.
        """
        session = get_intel_session()
        if session is None:
            return []
        try:
            # Filtre SQL minimal pour réduire le jeu — la vérification stricte
            # de version se fait en Python via _version_in_range.
            rows = session.query(IntelCVE).filter(
                IntelCVE.description.ilike(f"%{service_name}%")
            ).all()

            confirmed = []
            for row in rows:
                entry = self._row_to_dict(row)
                ranges = entry.get("affected_versions", [])
                if ranges and self._version_in_range(version, ranges):
                    confirmed.append(entry)

            if not confirmed:
                logger.info(
                    "Aucune CVE confirmée localement pour %s %s. "
                    "Mettre à jour avec : cd siati_intel_builder && python main.py",
                    service_name, version,
                )
            return confirmed
        finally:
            session.close()

    def _version_in_range(self, target: str, ranges: list) -> bool:
        """
        Comparaison stricte via packaging.version.
        Supporte les formats NVD : version_start_including / version_end_excluding.
        Ne retourne jamais True par défaut ou par similarité de nom.
        """
        try:
            v_target = Version(target)
        except InvalidVersion:
            logger.warning("Version non parseable : %r", target)
            return False

        for r in ranges:
            try:
                if isinstance(r, dict):
                    v_min = Version(r["version_start_including"]) if "version_start_including" in r else None
                    v_max = Version(r["version_end_excluding"]) if "version_end_excluding" in r else None
                    v_max_inc = Version(r["version_end_including"]) if "version_end_including" in r else None

                    if v_min and v_max and v_min <= v_target < v_max:
                        return True
                    if v_min and v_max_inc and v_min <= v_target <= v_max_inc:
                        return True
                    if v_min and not v_max and not v_max_inc and v_target >= v_min:
                        return True
                elif isinstance(r, str):
                    if Version(r) == v_target:
                        return True
            except InvalidVersion:
                continue

        return False

    @staticmethod
    def _row_to_dict(row: IntelCVE) -> dict:
        d = {
            "cve_id": row.cve_id,
            "description": row.description,
            "cvss_score": row.cvss_v3_score or row.cvss_v2_score,
            "cvss_vector": row.cvss_v3_vector,
            "cwe_id": row.cwe_id,
        }
        # Champs JSON optionnels — ajoutés si présents dans le schéma
        for field in ("affected_versions", "fixed_versions", "keywords"):
            raw = getattr(row, field, None)
            d[field] = json.loads(raw) if raw else []
        d["poc_available"] = bool(getattr(row, "poc_available", False))
        return d
