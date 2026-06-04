"""
data_manager.py
===============
Centralise la gestion du cycle de vie des données pour le ML.
Responsable du chargement, nettoyage, fusion et versionnement (train/test).

Produit les 31 colonnes brutes attendues par engineer_features() :
    CVE  : cvss_score, severity_num, av_num, ac_num, pr_num, ui_num,
           epss, is_exploited, age_cve
    Hôte : port, is_public, host_type, host_criticality
    + vuln_id pour le mapping en base.
"""
import logging
from pathlib import Path
from typing import Optional, Tuple

import pandas as pd
import numpy as np
from sqlalchemy.orm import Session

from sqlalchemy import select
from app.db.models import Exploit, Host, Service, Vulnerability
from app.core.ml.features import (
    get_training_features,
    engineer_features,
    FEATURE_COLS,
    RAW_COLS_NEEDED,
    AV_NUM, AC_NUM, PR_NUM, UI_NUM, SEVERITY_NUM,
    classify_service,
)

logger = logging.getLogger(__name__)

DATA_DIR = Path("data")
GOLD_DATASET_PATH = DATA_DIR / "entrainement_dataset.csv"
TRAIN_SET_PATH = DATA_DIR / "train.csv"
TEST_SET_PATH = DATA_DIR / "test.csv"
CURRENT_YEAR = 2026

class DataManager:
    def __init__(self, data_dir: Path = DATA_DIR):
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.df: Optional[pd.DataFrame] = None

    def extract_real_data(self, session: Session) -> pd.DataFrame:
        """
        Extrait les données de la DB locale et les formate pour l'inférence ML.
        Produit les 31 colonnes attendues par engineer_features().
        """
        query = (
            select(
                Vulnerability.id.label("vuln_id"),
                Vulnerability.cve,
                Vulnerability.cvss_score,
                Vulnerability.cvss_vector,
                Vulnerability.epss_score,
                Vulnerability.is_kev,
                Service.port,
                Service.service,
                Host.ip.label("host_ip"),
                Exploit.disponible.label("has_exploit"),
            )
            .join(Service, Vulnerability.service_id == Service.id)
            .join(Host, Service.host_id == Host.id)
            .outerjoin(Exploit, Vulnerability.cve == Exploit.cve)
        )

        rows = session.execute(query).fetchall()
        if not rows:
            return pd.DataFrame()

        df = pd.DataFrame(rows)

        # ── Nettoyage de base ─────────────────────────────────────────────────
        df["cvss_score"] = pd.to_numeric(df["cvss_score"], errors="coerce").fillna(
            df["cvss_score"].median() if not df["cvss_score"].isna().all() else 5.0
        )
        df["has_exploit"] = df["has_exploit"].fillna(False).astype(int)
        df["is_kev"] = df["is_kev"].fillna(False).astype(int)
        # Exploité si présent dans Exploit-DB ou dans la CISA KEV
        df["is_exploited"] = (df["has_exploit"] | df["is_kev"]).astype(int)

        # ── severity_num depuis cvss_score ────────────────────────────────────
        def cvss_to_severity_num(score: float) -> int:
            if score >= 9.0: return 4
            if score >= 7.0: return 3
            if score >= 4.0: return 2
            if score > 0.0:  return 1
            return 0
        df["severity_num"] = df["cvss_score"].apply(cvss_to_severity_num)

        # ── Parsing vecteur CVSS ──────────────────────────────────────────────
        def parse_cvss_component(vector_str, component):
            if not isinstance(vector_str, str):
                return "UNKNOWN"
            for part in vector_str.split("/"):
                if part.startswith(component + ":"):
                    return part.split(":")[1]
            return "UNKNOWN"

        df["av_num"] = df["cvss_vector"].apply(lambda v: AV_NUM.get(parse_cvss_component(v, "AV"), 0)).fillna(0).astype(int)
        df["ac_num"] = df["cvss_vector"].apply(lambda v: AC_NUM.get(parse_cvss_component(v, "AC"), 1)).fillna(1).astype(int)
        df["pr_num"] = df["cvss_vector"].apply(lambda v: PR_NUM.get(parse_cvss_component(v, "PR"), 0)).fillna(0).astype(int)
        df["ui_num"] = df["cvss_vector"].apply(lambda v: UI_NUM.get(parse_cvss_component(v, "UI"), 1)).fillna(1).astype(int)

        # Heuristique pour vecteurs manquants
        mask_no_vector = df["cvss_vector"].isna() | (df["cvss_vector"] == "")
        if mask_no_vector.any():
            high_cvss = mask_no_vector & (df["cvss_score"] >= 7.0)
            df.loc[high_cvss & (df["av_num"] == 0), "av_num"] = 4  # NETWORK
            df.loc[high_cvss & (df["ac_num"] == 0), "ac_num"] = 2  # LOW

        # ── EPSS (issu de la DB d'enrichissement locale) ──────────────────────────────
        df["epss"] = df["epss_score"].fillna(0.0)

        # ── Age CVE ───────────────────────────────────────────────────────────
        df["age_cve"] = df["cve"].apply(
            lambda x: CURRENT_YEAR - int(x.split("-")[1]) if isinstance(x, str) and "-" in x else 6
        )

        # ── Features hôte dérivées depuis l'IP et le port ─────────────────────
        #
        # is_public : 1 si l'IP n'est PAS dans un bloc RFC-1918 / loopback
        def _is_public_ip(ip: str) -> int:
            try:
                import ipaddress
                addr = ipaddress.ip_address(str(ip).strip())
                return 0 if (addr.is_private or addr.is_loopback or addr.is_link_local) else 1
            except Exception:
                return 0

        df["is_public"] = df["host_ip"].apply(_is_public_ip)

        # host_type : 0=inconnu 1=client 2=serveur 3=infra critique
        # heuristique : ports < 1024 ouverts → serveur ; ports critiques → infra
        INFRA_PORTS  = {22, 23, 25, 53, 3389, 5900, 161, 162}
        SERVER_PORTS = {80, 443, 8080, 8443, 21, 3306, 5432, 1433, 27017}

        def _host_type(port: int) -> int:
            p = int(port) if port else 0
            if p in INFRA_PORTS:  return 3
            if p in SERVER_PORTS: return 2
            if p < 1024:          return 2  # port système → serveur probable
            return 1

        df["host_type"] = df["port"].apply(_host_type)

        # host_criticality [0-3] : combinaison is_public + host_type + cvss
        df["host_criticality"] = (
            df["is_public"] * 1 +
            (df["host_type"] >= 2).astype(int) * 1 +
            (df["cvss_score"] >= 7.0).astype(int) * 1
        ).clip(0, 3).astype(int)

        logger.info("Données extraites de la DB : %d vulnérabilités", len(df))
        return df

    def load_official_data(self) -> pd.DataFrame:
        """Charge et pré-encode les données NVD."""
        path = self.data_dir / "nvd_training_data.csv"
        if not path.exists():
            return pd.DataFrame()
        df = pd.read_csv(path)
        
        # Encodage des features qualitatives
        if "attackVector" in df.columns and "av_num" not in df.columns:
            df["av_num"] = df["attackVector"].map(lambda x: AV_NUM.get(str(x).upper(), 0) if pd.notna(x) else 0)
        if "attackComplexity" in df.columns and "ac_num" not in df.columns:
            df["ac_num"] = df["attackComplexity"].map(lambda x: AC_NUM.get(str(x).upper(), 0) if pd.notna(x) else 0)
        if "privilegesRequired" in df.columns and "pr_num" not in df.columns:
            df["pr_num"] = df["privilegesRequired"].map(lambda x: PR_NUM.get(str(x).upper(), 0) if pd.notna(x) else 0)
        if "userInteraction" in df.columns and "ui_num" not in df.columns:
            df["ui_num"] = df["userInteraction"].map(lambda x: UI_NUM.get(str(x).upper(), 0) if pd.notna(x) else 0)
        if "severity" in df.columns and "severity_num" not in df.columns:
            df["severity_num"] = df["severity"].map(lambda x: SEVERITY_NUM.get(str(x).upper(), 0) if pd.notna(x) else 0)

        # Alignement des noms de colonnes avec le dataset d'entraînement
        if "epss_score" in df.columns and "epss" not in df.columns:
            df["epss"] = df["epss_score"]
        if "has_exploit" in df.columns and "is_exploited" not in df.columns:
            df["is_exploited"] = df["has_exploit"]
            
        return df

    def prepare_unified_dataset(self, session: Optional[Session] = None, target_size: int = 500) -> pd.DataFrame:
        """Charge, fusionne et nettoie les données officielles et locales."""
        logger.info("🚀 Chargement du dataset professionnel unifié...")
        
        # Priorité au dataset consolidé professionnel
        if GOLD_DATASET_PATH.exists():
            logger.info(f"Chargement direct de {GOLD_DATASET_PATH}")
            self.df = pd.read_csv(GOLD_DATASET_PATH)
        else:
            logger.info("Dataset consolidé absent, repli sur NVD + local...")
            df_off = self.load_official_data()
            df_loc = self.extract_real_data(session) if session else pd.DataFrame()
            self.df = pd.concat([df_loc, df_off], ignore_index=True).drop_duplicates(subset=["cve"], keep="first")
            
        self._clean_data()
        return self.df

    def _clean_data(self):
        """Nettoyage rigoureux des données."""
        if self.df is None or self.df.empty:
            return

        # Remplissage des NaNs pour les colonnes critiques
        self.df["cvss_score"] = pd.to_numeric(self.df["cvss_score"], errors="coerce").fillna(5.0)
        
        # Assurer la présence des colonnes brutes
        for col in ["is_exploited", "epss", "is_public", "host_criticality"]:
            if col not in self.df.columns:
                self.df[col] = 0
            self.df[col] = pd.to_numeric(self.df[col], errors="coerce").fillna(0)

        for col in ["severity_num", "av_num", "ac_num", "pr_num", "ui_num", "host_type", "port"]:
            if col not in self.df.columns:
                self.df[col] = 0
            self.df[col] = self.df[col].fillna(0).astype(int)

        # Bornage
        self.df["cvss_score"] = self.df["cvss_score"].clip(0, 10)

    def split_and_save(self, test_size: float = 0.2, random_state: int = 42) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Découpe en train/test et persiste les fichiers."""
        if self.df is None or self.df.empty:
            raise ValueError("Dataset vide. Appelez prepare_unified_dataset() d'abord.")

        shuffled = self.df.sample(frac=1, random_state=random_state).reset_index(drop=True)
        
        split_idx = int(len(shuffled) * (1 - test_size))
        train_df = shuffled.iloc[:split_idx]
        test_df = shuffled.iloc[split_idx:]
        
        train_df.to_csv(TRAIN_SET_PATH, index=False)
        test_df.to_csv(TEST_SET_PATH, index=False)
        
        logger.info("📊 Split Train (%d) / Test (%d) sauvegardé.", len(train_df), len(test_df))
        return train_df, test_df

    def get_report(self) -> str:
        """Génère un rapport textuel sur la qualité des données."""
        if self.df is None or self.df.empty:
            return "Dataset vide."
            
        report = []
        report.append(f"=== RAPPORT DE DONNÉES ML ===")
        report.append(f"Total entries : {len(self.df)}")
        
        cve_col = "cve_id" if "cve_id" in self.df.columns else "cve" if "cve" in self.df.columns else None
        if cve_col:
            report.append(f"Duplicates    : {self.df[cve_col].duplicated().sum()}")
        
        report.append(f"Missing Values:\n{self.df.isna().sum().to_string()}")
        
        if "risk_score" in self.df.columns:
            report.append(f"\nDistribution du Score de Risque:")
            report.append(self.df["risk_score"].describe().to_string())
        
        expl_col = "is_exploited" if "is_exploited" in self.df.columns else "has_exploit" if "has_exploit" in self.df.columns else None
        if expl_col:
            report.append(f"\nDistribution is_exploited:")
            report.append(self.df[expl_col].value_counts(normalize=True).to_string())
        report.append("=============================")
        
        return "\n".join(report)

def get_prepared_features(file_path: Path) -> Tuple[pd.DataFrame, pd.Series]:
    """Charge un CSV préparé et extrait (X, y)."""
    df = pd.read_csv(file_path)
    return get_training_features(df)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    from app.db.database import get_session
    
    dm = DataManager()
    session = get_session()
    
    try:
        dm.prepare_unified_dataset(session=session)
        dm.split_and_save()
        print("\n" + dm.get_report())
    finally:
        session.close()
