from fastapi import APIRouter

from app.api.routers import auth, system, stats, hosts, vulnerabilities, reports, playbooks, scans, ml, branding

api_router = APIRouter()

api_router.include_router(auth.router)
api_router.include_router(system.router)
api_router.include_router(stats.router)
api_router.include_router(hosts.router)
api_router.include_router(vulnerabilities.router)
api_router.include_router(reports.router)
api_router.include_router(playbooks.router)
api_router.include_router(scans.router)
api_router.include_router(ml.router)
api_router.include_router(branding.router)
