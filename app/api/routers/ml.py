from pathlib import Path
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from app.db.database import get_session
from app.core.security import require_auth

ROOT = Path(__file__).resolve().parents[3]
router = APIRouter(prefix="/api", tags=["ml"])

@router.post("/score")
def run_ml_score(_auth=Depends(require_auth)):
    session = get_session()
    try:
        from app.core.ml.data_manager import DataManager
        from app.core.ml.predict import predict_and_store
        dm = DataManager()
        df = dm.extract_real_data(session)
        if df.empty:
            return {"ok": False, "error": "Aucune donnée en base"}
        stats = predict_and_store(session, df)
        return {"ok": True, "scored": stats}
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})
    finally:
        session.close()

@router.get("/performance")
def get_model_performance():
    metrics_path = ROOT / "data" / "metrics_xgb.json"
    report_path = ROOT / "data" / "evaluation" / "performance_report.md"
    
    performance_data = {
        "metrics": None,
        "report_md": None,
        "plots": [
            {"id": "actual_vs_predicted", "path": "/data/evaluation/01_actual_vs_predicted.png"},
            {"id": "feature_importance", "path": "/data/evaluation/02_feature_importance.png"},
            {"id": "residuals", "path": "/data/evaluation/03_residuals.png"},
            {"id": "learning_curve", "path": "/data/evaluation/04_learning_curve.png"},
            {"id": "dataset_overview", "path": "/data/evaluation/05_dataset_overview.png"},
            {"id": "confusion_matrix", "path": "/data/evaluation/06_confusion_matrix.png"},
        ]
    }
    
    if metrics_path.exists():
        import json
        with open(metrics_path, "r") as f:
            performance_data["metrics"] = json.load(f)
            
    if report_path.exists():
        performance_data["report_md"] = report_path.read_text(encoding="utf-8")
        
    return performance_data
