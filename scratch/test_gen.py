import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(ROOT))

from app.db.database import get_session
from app.core.llm.generator import generate_playbook_for_vulnerability
from app.db.models import Report

def test_generation():
    db = get_session()
    vuln_id = 2  # SSH 7.6p1
    
    print(f"Triggering Audit generation for Vuln ID {vuln_id}...")
    report_id = generate_playbook_for_vulnerability(db, vuln_id, mode="audit")
    
    if report_id:
        report = db.get(Report, report_id)
        print("\n--- GENERATED REPORT ---")
        print(report.content_md)
        print("------------------------")
    else:
        print("Generation failed.")

if __name__ == "__main__":
    test_generation()
