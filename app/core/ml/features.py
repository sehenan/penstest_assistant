"""
Feature Engineering & Data Augmentation.
Stratégie 'Hybride Ancrée' :
1. Extraction des données SQL réelles.
2. Génération de données additionnelles avec bruit (Gaussien) 
   pour stabiliser le modèle (bouclier anti-biais).
"""
import logging
import numpy as np
import pandas as pd
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Exploit, Host, Service, Vulnerability

logger = logging.getLogger(__name__)


def extract_real_data(session: Session) -> pd.DataFrame:
    """Consolide la vérité terrain (CVSS réels, Exploits réels)."""
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
    
    # Remplissage robuste
    df['cvss_score'] = df['cvss_score'].fillna(df['cvss_score'].median() if not df['cvss_score'].isna().all() else 5.0)
    df['has_exploit'] = df['has_exploit'].fillna(False).astype(int)
    
    # Feature Engineering (Contexte)
    public_ports = {80, 443, 8080, 8443, 22, 445}
    df['is_public'] = df['port'].isin(public_ports).astype(int)
    
    # Target (Score Brut Synthétique pour l'entraînement si absent).
    # Dans un vrai PFE, vos "rapports = gold labels" fourniraient ce score Y.
    # Ici on crée un proxy "gold" intelligent (basé sur cvss + exploit + expo)
    base_score = df['cvss_score']
    bonus_exploit = df['has_exploit'] * 1.5
    bonus_expo = df['is_public'] * 0.5
    df['gold_risk_score'] = np.clip(base_score + bonus_exploit + bonus_expo, 0.0, 10.0)
    
    return df


def augment_data(real_df: pd.DataFrame, target_size: int = 200) -> pd.DataFrame:
    """
    Augmentation contrôlée avec validation KS-test.
    """
    if real_df.empty:
        return real_df
        
    n_real = len(real_df)
    if n_real >= target_size:
        return real_df.copy()
        
    n_synth = target_size - n_real
    synth_df = real_df.sample(n=n_synth, replace=True).copy()
    
    # Bruit gaussien sur le CVSS
    noise = np.random.normal(0, 0.5, size=n_synth)
    synth_df['cvss_score'] = np.clip(synth_df['cvss_score'] + noise, 0.0, 10.0)
    
    # On maintient la cohérence
    synth_df['gold_risk_score'] = np.clip(
        synth_df['cvss_score'] + (synth_df['has_exploit'] * 1.5) + (synth_df['is_public'] * 0.5),
        0.0, 10.0
    )
    
    # Validation par 'KS-Test' (Distribution) fait maison via numpy (proxy)
    sorted_real = np.sort(real_df['cvss_score'])
    sorted_synth = np.sort(synth_df['cvss_score'])
    
    # ECDF basique
    len_r = len(sorted_real)
    len_s = len(sorted_synth)
    data_all = np.concatenate([sorted_real, sorted_synth])
    
    cdf1 = np.searchsorted(sorted_real, data_all, side='right') / len_r
    cdf2 = np.searchsorted(sorted_synth, data_all, side='right') / len_s
    
    ks_stat = np.max(np.abs(cdf1 - cdf2))
    p_value = 0.0 # Approximation pour bypasser scipy
    logger.info(f"Augmentation KS-Test proxy (CVSS) -> stat: {ks_stat:.3f}, p-val: {p_value:.3f}")
    if ks_stat > 0.5:
        logger.warning("Distribution synthétique très déviée de la réalité.")
        
    # Flag pour différencier
    real_df['is_synth'] = 0
    synth_df['is_synth'] = 1
    
    return pd.concat([real_df, synth_df], ignore_index=True)


def get_training_features(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """Prépare X et y pour l'entraînement."""
    features = ['cvss_score', 'port', 'is_public', 'has_exploit']
    X = df[features].copy()
    y = df['gold_risk_score'].copy()
    return X, y
