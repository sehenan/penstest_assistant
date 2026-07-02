"""
Tests unitaires du pipeline ML (priorisation XGBoost v2).

L'API v1 (`augment_data`, `train_and_save_model`) a été remplacée par :
  - feature engineering sans fuite de données (`features.py`)
  - inférence via modèles pré-entraînés (`predict.predict_and_store`)
Ces tests couvrent l'API réelle actuelle.
"""
import pandas as pd
import pytest

from app.core.ml.features import (
    FEATURE_COLS,
    classify_service,
    engineer_features,
    get_training_features,
)
from app.core.ml.predict import predict_and_store, MODEL_REG_PATH, MODEL_CLF_PATH
from app.db.models import Host, Service, Vulnerability, ScoreML


def _raw_df(vuln_ids=None):
    """DataFrame minimal simulant la sortie de DataManager.extract_real_data."""
    n = len(vuln_ids) if vuln_ids is not None else 3
    data = {
        "epss": [0.05, 0.5, 0.95][:n],
        "age_cve": [3, 18, 40][:n],
        "ac_num": [1, 2, 1][:n],
        "pr_num": [0, 1, 0][:n],
        "ui_num": [0, 0, 1][:n],
        "host_type": [0, 1, 1][:n],
        "port": [80, 22, 3306][:n],
    }
    if vuln_ids is not None:
        data["vuln_id"] = vuln_ids
    return pd.DataFrame(data)


def test_classify_service_buckets():
    """Les ports web partagent une classe, distincte des ports d'accès distant."""
    assert classify_service(80) == classify_service(443)
    assert classify_service(80) != classify_service(22)
    assert isinstance(classify_service(9999), int)


def test_engineer_features_shape_and_columns():
    """engineer_features renvoie EXACTEMENT les colonnes attendues par le modèle."""
    X = engineer_features(_raw_df())
    assert list(X.columns) == FEATURE_COLS
    assert len(X) == 3


def test_engineer_features_imputes_missing_columns():
    """Les colonnes brutes manquantes sont imputées à 0 (aucun NaN en sortie)."""
    X = engineer_features(pd.DataFrame({"port": [80, 22]}))
    assert list(X.columns) == FEATURE_COLS
    assert X.notna().all().all()


def test_get_training_features_uses_ops_risk_score():
    """La cible y est prélevée sur ops_risk_score quand présent."""
    df = _raw_df()
    df["ops_risk_score"] = [1.0, 5.0, 9.0]
    X, y = get_training_features(df)
    assert list(X.columns) == FEATURE_COLS
    assert list(y) == [1.0, 5.0, 9.0]


@pytest.mark.skipif(
    not (MODEL_REG_PATH.exists() and MODEL_CLF_PATH.exists()),
    reason="Modèles XGBoost pré-entraînés absents (data/model/*.joblib)",
)
def test_predict_and_store_persists_scores(db_session):
    """Inférence de bout en bout : chaque vuln reçoit un ScoreML (label + score)."""
    host = Host(ip="10.0.0.1")
    db_session.add(host)
    db_session.flush()
    svc = Service(host_id=host.id, port=80, protocol="tcp")
    db_session.add(svc)
    db_session.flush()
    vulns = [Vulnerability(service_id=svc.id, cve=f"CVE-2021-{i}") for i in range(1, 4)]
    db_session.add_all(vulns)
    db_session.commit()

    df = _raw_df(vuln_ids=[v.id for v in vulns])
    stats = predict_and_store(db_session, df)

    assert stats["scored"] == 3
    assert stats["failed"] == 0
    for v in vulns:
        row = db_session.query(ScoreML).filter(ScoreML.vuln_id == v.id).first()
        assert row is not None
        assert row.label in {"Faible", "Moyenne", "Haute", "Critique"}
        assert row.score is not None


def test_predict_and_store_empty_df_noop(db_session):
    """Un DataFrame vide ne provoque ni écriture ni erreur."""
    stats = predict_and_store(db_session, pd.DataFrame())
    assert stats == {"scored": 0, "failed": 0}
