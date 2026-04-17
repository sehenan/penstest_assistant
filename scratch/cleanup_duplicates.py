"""
Script de nettoyage des doublons dans la base de données.
Supprime les vulnérabilités et services redondants.
"""
from sqlalchemy import select, func
from app.db.database import get_session, init_db
from app.db.models import Host, Service, Vulnerability, ScoreML, Report

def cleanup():
    init_db()
    session = get_session()
    try:
        # 1. Nettoyage des vulnérabilités en double (même service_id et cve/description)
        print("Nettoyage des vulnérabilités en double...")
        vulns = session.query(Vulnerability).all()
        seen = set()
        to_delete = []
        for v in vulns:
            key = (v.service_id, v.cve, v.description)
            if key in seen:
                to_delete.append(v)
            else:
                seen.add(key)
        
        for v in to_delete:
            print(f" Supprimé: Vuln ID {v.id} (CVE: {v.cve})")
            session.delete(v)
        
        session.commit()
        print(f"Total vulnérabilités supprimées : {len(to_delete)}")

        # 2. Nettoyage des services en double (même host_id, port, protocol)
        print("\nNettoyage des services en double...")
        services = session.query(Service).all()
        seen_svc = set()
        to_delete_svc = []
        for s in services:
            key = (s.host_id, s.port, s.protocol)
            if key in seen_svc:
                to_delete_svc.append(s)
            else:
                seen_svc.add(key)
        
        for s in to_delete_svc:
            print(f" Supprimé: Service ID {s.id} (Port: {s.port})")
            session.delete(s)
            
        session.commit()
        print(f"Total services supprimés : {len(to_delete_svc)}")

    except Exception as e:
        print(f"Erreur lors du nettoyage : {e}")
        session.rollback()
    finally:
        session.close()

if __name__ == "__main__":
    cleanup()
