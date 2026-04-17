"""
data_manager.py
===============
Centralise la gestion du cycle de vie des données pour le ML.
Responsable du chargement, nettoyage, fusion et versionnement (train/test).
"""
import logging
from pathlib import Path
from typing import Optional, Tuple

import pandas as pd
import numpy as np
from sqlalchemy.orm import Session

from sqlalchemy import select
from app.db.models import Exploit, Service, Vulnerability
from app.core.ml.features import (
    get_training_features,
    FEATURE_COLS
)

logger = logging.getLogger(__name__)

DATA_DIR = Path("data")
GOLD_DATASET_PATH = DATA_DIR / "gold_dataset.csv"
TRAIN_SET_PATH = DATA_DIR / "train.csv"
TEST_SET_PATH = DATA_DIR / "test.csv"

class DataManager:
    def __init__(self, data_dir: Path = DATA_DIR):
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.df: Optional[pd.DataFrame] = None

    def extract_real_data(self, session: Session) -> pd.DataFrame:
        """Consolide la vérité terrain depuis les scans ingérés (DB locale)."""
        query = (
            select(
                Vulnerability.id.label("vuln_id"),
                Vulnerability.cve,
                Vulnerability.cvss_score,
                Service.port,
                Service.service,
                Exploit.disponible.label("has_exploit"),
            )
            .join(Service, Vulnerability.service_id == Service.id)
            .outerjoin(Exploit, Vulnerability.cve == Exploit.cve)
        )

        rows = session.execute(query).fetchall()
        if not rows:
            return pd.DataFrame()

        df = pd.DataFrame(rows)
        df["cvss_score"] = df["cvss_score"].fillna(
            df["cvss_score"].median() if not df["cvss_score"].isna().all() else 5.0
        )
        df["has_exploit"] = df["has_exploit"].fillna(False).astype(int)
        public_ports = {80, 443, 8080, 8443, 22, 445}
        df["is_public"] = df["port"].isin(public_ports).astype(int)
        df["gold_risk_score"] = np.clip(
            df["cvss_score"] + df["has_exploit"] * 1.5 + df["is_public"] * 0.5,
            0.0, 10.0
        )
        for col in ["severity_num", "in_cisa_kev", "in_exploitdb", "av_num", "ac_num", "pr_num", "ui_num"]:
            df[col] = 0
            
        return df

    def load_official_data(self) -> pd.DataFrame:
        """Charge et pré-encode les données NVD."""
        path = self.data_dir / "nvd_training_data.csv"
        if not path.exists():
            return pd.DataFrame()
        df = pd.read_csv(path)
        
        # Encodage des features qualitatives pour la fusion
        from app.core.ml.features import AV_NUM, AC_NUM, PR_NUM, UI_NUM, SEVERITY_NUM
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
            
        return df

    def augment_data(self, real_df: pd.DataFrame, target_size: int = 500) -> pd.DataFrame:
        """Augmentation de données avec bruit gaussien."""
        if real_df.empty or len(real_df) >= target_size:
            return real_df
        
        n_synth = target_size - len(real_df)
        synth_df = real_df.sample(n=n_synth, replace=True, random_state=42).copy()
        noise = np.random.default_rng(42).normal(0, 0.5, size=n_synth)
        synth_df["cvss_score"] = np.clip(synth_df["cvss_score"] + noise, 0.0, 10.0)
        synth_df["gold_risk_score"] = np.clip(
            synth_df["cvss_score"] + synth_df["has_exploit"] * 1.5 + synth_df["is_public"] * 0.5,
            0.0, 10.0
        )
        real_df = real_df.copy()
        real_df["is_synth"] = 0
        synth_df["is_synth"] = 1
        return pd.concat([real_df, synth_df], ignore_index=True)

    def prepare_unified_dataset(self, session: Optional[Session] = None, target_size: int = 500) -> pd.DataFrame:
        """Charge, fusionne et nettoie les données officielles et locales."""
        logger.info("🚀 Préparation du dataset unifié...")
        df_off = self.load_official_data()
        df_loc = self.extract_real_data(session) if session else pd.DataFrame()
        
        if df_off.empty and df_loc.empty:
            logger.error("❌ Aucune donnée source trouvée.")
            return pd.DataFrame()
            
        self.df = pd.concat([df_loc, df_off], ignore_index=True).drop_duplicates(subset=["cve"], keep="first")
        if len(self.df) < target_size:
            self.df = self.augment_data(self.df, target_size=target_size)
        
        self._clean_data()
        self.df.to_csv(GOLD_DATASET_PATH, index=False)
        return self.df

    def _clean_data(self):
        """Nettoyage rigoureux des données."""
        if self.df is None or self.df.empty:
            return

        # Remplissage des NaNs pour les colonnes critiques
        self.df["cvss_score"] = pd.to_numeric(self.df["cvss_score"], errors="coerce").fillna(5.0)
        self.df["gold_risk_score"] = pd.to_numeric(self.df["gold_risk_score"], errors="coerce").fillna(self.df["cvss_score"])
        
        # S'assurer que les types sont corrects
        for col in ["has_exploit", "is_public", "in_cisa_kev", "in_exploitdb"]:
            if col in self.df.columns:
                self.df[col] = self.df[col].fillna(0).astype(int)

        # Bornage des scores (0-10)
        self.df["cvss_score"] = self.df["cvss_score"].clip(0, 10)
        self.df["gold_risk_score"] = self.df["gold_risk_score"].clip(0, 10)

    def split_and_save(self, test_size: float = 0.2, random_state: int = 42) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Découpe en train/test et persiste les fichiers.
        """
        if self.df is None or self.df.empty:
            raise ValueError("Dataset vide. Appelez prepare_unified_dataset() d'abord.")

        # On mélange tout avant de splitter
        shuffled = self.df.sample(frac=1, random_state=random_state).reset_index(drop=True)
        
        split_idx = int(len(shuffled) * (1 - test_size))
        train_df = shuffled.iloc[:split_idx]
        test_df = shuffled.iloc[split_idx:]
        
        train_df.to_csv(TRAIN_SET_PATH, index=False)
        test_df.to_csv(TEST_SET_PATH, index=False)
        
        logger.info("📊 Split Train (%d) / Test (%d) sauvegardé.", len(train_df), len(test_df))
        return train_df, test_df

    def get_report(self) -> str:
        """Génère un rapport textuel sur la qualité des données (similaire au notebook)."""
        if self.df is None or self.df.empty:
            return "Dataset vide."
            
        report = []
        report.append(f"=== RAPPORT DE DONNÉES ML ===")
        report.append(f"Total entries : {len(self.df)}")
        report.append(f"Duplicates    : {self.df['cve'].duplicated().sum()}")
        report.append(f"Missing Values:\n{self.df.isna().sum().to_string()}")
        report.append(f"\nDistribution du Score de Risque (Gold):")
        report.append(self.df["gold_risk_score"].describe().to_string())
        report.append(f"\nLabel has_exploit distribution:")
        report.append(self.df["has_exploit"].value_counts(normalize=True).to_string())
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
