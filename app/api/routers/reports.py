from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse, Response
from app.db.database import get_session
from app.db.models import Vulnerability, Report
from app.core.security import require_auth

router = APIRouter(prefix="/api/reports", tags=["reports"])

@router.get("")
def get_reports():
    session = get_session()
    try:
        reports = session.query(Report).order_by(Report.timestamp.desc()).all()
        result = []
        for r in reports:
            v = session.query(Vulnerability).filter(Vulnerability.id == r.vuln_id).first()
            result.append({
                "id": r.id,
                "title": r.title,
                "stage": r.stage,
                "cve": v.cve if v else None,
                "ts": r.timestamp.isoformat(),
                "size": len(r.content_md or ""),
            })
        return result
    finally:
        session.close()

@router.get("/{report_id}")
def get_report_content(report_id: int):
    session = get_session()
    try:
        r = session.query(Report).filter(Report.id == report_id).first()
        if not r:
            raise HTTPException(status_code=404, detail="Rapport introuvable")
        return {
            "id": r.id,
            "title": r.title,
            "stage": r.stage,
            "content_md": r.content_md,
            "ts": r.timestamp.isoformat(),
        }
    finally:
        session.close()

@router.get("/{report_id}/pdf")
def get_report_pdf(report_id: int):
    session = get_session()
    try:
        import markdown
        from xhtml2pdf import pisa
        from io import BytesIO
        
        r = session.query(Report).filter(Report.id == report_id).first()
        if not r:
            raise HTTPException(status_code=404, detail="Rapport introuvable")
        
        md_content = r.content_md or ""
        md_content = md_content.replace("# RAPPORT DE AUDIT TECHNIQUE\n", "")
        md_content = md_content.replace("# RAPPORT DE PAYLOAD TECHNIQUE\n", "")
        import re
        md_content = re.sub(r'(?i)^#\s*Rapport technique.*?\n', '', md_content, flags=re.MULTILINE)
        html_content = markdown.markdown(md_content, extensions=['tables', 'fenced_code'])
        
        date_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
        title = r.title or "Rapport d'Audit"

        full_html = f"""
        <!DOCTYPE html>
        <html lang="fr">
        <head>
        <meta charset="UTF-8">
        <title>{title}</title>
        <style>
          @page {{
              size: A4;
              margin: 1.5cm;
              @frame footer {{
                  -pdf-frame-content: footerContent;
                  bottom: 1cm;
                  margin-left: 1.5cm;
                  margin-right: 1.5cm;
                  height: 1cm;
              }}
          }}
          body {{ font-family: Helvetica, Arial, sans-serif; font-size: 10pt; color: #1f2937; line-height: 1.5; }}
          h1 {{ color: #f97316; font-size: 18pt; border-bottom: 1px solid #e5e7eb; padding-bottom: 5px; }}
          h2 {{ color: #374151; font-size: 14pt; margin-top: 15px; }}
          h3 {{ color: #4b5563; font-size: 12pt; }}
          table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
          th {{ background-color: #f3f4f6; color: #1f2937; font-weight: bold; padding: 6px; border: 1px solid #d1d5db; text-align: left; }}
          td {{ padding: 6px; border: 1px solid #e5e7eb; }}
          pre {{ background-color: #111827; color: #a6e3a1; padding: 10px; border-radius: 4px; font-size: 9pt; white-space: pre-wrap; }}
          code {{ font-family: Courier, monospace; background-color: #f3f4f6; padding: 2px 4px; border-radius: 3px; color: #e11d48; }}
          blockquote {{ border-left: 4px solid #f97316; margin-left: 0; padding-left: 10px; color: #6b7280; font-style: italic; background-color: #fff7ed; padding: 8px; }}
          .brand {{ color: #f97316; font-weight: bold; font-size: 20pt; }}
          .header {{ text-align: center; font-size: 10pt; color: #6b7280; margin-bottom: 25px; border-bottom: 1px solid #e5e7eb; padding-bottom: 15px; }}
        </style>
        </head>
        <body>
          <div class="header">
             <img src="app/ui/assets/logo.png" style="height: 50px; margin-bottom: 10px;" /><br>
             <span class="brand">SIATI</span><br>
             Système Intelligent d'Assistance aux Tests d'Intrusion<br>
             Généré le {date_str}
          </div>
          <div style="font-size: 16pt; font-weight: 700; color: #111827; margin-bottom: 18px; padding-bottom: 10px; border-bottom: 2px solid #f97316;">RAPPORT D'AUDIT TECHNIQUE</div>
          {html_content}
          
          <div id="footerContent" style="text-align: right; font-size: 8pt; color: #9ca3af; border-top: 1px solid #e5e7eb; padding-top: 5px;">
              SIATI — Pentest Intelligence Platform | Page <pdf:pagenumber> sur <pdf:pagecount>
          </div>
        </body>
        </html>
        """

        pdf_io = BytesIO()
        pisa_status = pisa.CreatePDF(
            full_html,
            dest=pdf_io,
            encoding='UTF-8'
        )

        if pisa_status.err:
            raise HTTPException(status_code=500, detail="Erreur lors de la génération du PDF")

        pdf_io.seek(0)
        
        headers = {
            'Content-Disposition': f'attachment; filename="report_{report_id}.pdf"'
        }
        return Response(content=pdf_io.read(), media_type="application/pdf", headers=headers)
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.delete("/{report_id}")
def delete_report(report_id: int, _auth=Depends(require_auth)):
    session = get_session()
    try:
        r = session.query(Report).filter(Report.id == report_id).first()
        if not r:
            raise HTTPException(status_code=404, detail="Rapport introuvable")
        session.delete(r)
        session.commit()
        return {"ok": True, "message": "Rapport supprimé"}
    except Exception as e:
        session.rollback()
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})
    finally:
        session.close()
