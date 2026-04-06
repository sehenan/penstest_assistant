"""
Tests unitaires pour le pipeline de Machine Learning (Priorisation XGBoost).
"""
import pandas as pd
from app.core.ml.features import augment_data, get_training_features
from app.core.ml.train import train_and_save_model, MODEL_PATH
from app.core.ml.predict import predict_and_store
from app.db.models import ScoreML, Vulnerability

def test_ml_pipeline(db_session):
    # Setup - on mock des données Vulnerability pour insérer un vrai fk
    v1 = Vulnerability(cve="CVE-X1", service_id=1)
    v2 = Vulnerability(cve="CVE-X2", service_id=1)
    v3 = Vulnerability(cve="CVE-X3", service_id=1)
    db_session.add_all([v1, v2, v3])
    db_session.commit()
    
    # 1. Feature Engineering (Mock Dataframe simulant la sortie de extract_real_data)
    df = pd.DataFrame({
        'vuln_id': [v1.id, v2.id, v3.id],
        'cvss_score': [9.8, 5.0, 3.2],
        'port': [443, 80, 22],
        'is_public': [1, 1, 0],
        'has_exploit': [1, 0, 0],
        'gold_risk_score': [11.8, 5.5, 3.2]
    })
    
    # Augmentation Synthétique contrôlée (cible=20)
    aug_df = augment_data(df, target_size=20)
    assert len(aug_df) == 20
    
    # Preparation X, y
    X, y = get_training_features(aug_df)
    assert 'cvss_score' in X.columns
    assert len(X) == 20
    
    # 2. Entraînement 
    train_and_save_model(X, y)
    assert MODEL_PATH.is_file()
    
    # 3. Prédiction (Inférence en direct)
    stats = predict_and_store(db_session, df)
    assert stats["scored"] == 3
    
    # Vérification BDD
    scores = db_session.query(ScoreML).all()
    assert len(scores) == 3
    # Le v1 qui a un score > 9.8 devrait être Critique
    c_scores = [s.label for s in scores]
    assert "Critique" in c_scores
    for s in scores:
        assert s.score > 0.0
