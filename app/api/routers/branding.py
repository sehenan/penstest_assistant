"""
SIATI — Branding API
Gestion du logo personnalisé de l'entreprise.
Le logo est stocké dans data/custom_logo.{ext} côté serveur.
"""
import os
import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import FileResponse

from app.core.security import require_auth

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/branding", tags=["branding"])

ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = ROOT / "data"

# Extensions autorisées et taille max (2 Mo)
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".svg", ".webp", ".gif"}
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 Mo

# Mapping extensions → MIME types
MIME_TYPES = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".svg": "image/svg+xml",
    ".webp": "image/webp",
    ".gif": "image/gif",
}


def _find_custom_logo() -> Path | None:
    """Cherche un fichier custom_logo.* dans data/."""
    for ext in ALLOWED_EXTENSIONS:
        candidate = DATA_DIR / f"custom_logo{ext}"
        if candidate.exists():
            return candidate
    return None


def _cleanup_old_logos():
    """Supprime tous les anciens fichiers custom_logo.* avant un nouvel upload."""
    for ext in ALLOWED_EXTENSIONS:
        candidate = DATA_DIR / f"custom_logo{ext}"
        if candidate.exists():
            candidate.unlink()


@router.get("/logo")
@router.head("/logo")
def get_custom_logo():
    """Retourne le logo personnalisé s'il existe, sinon 404."""
    logo_path = _find_custom_logo()
    if logo_path is None:
        raise HTTPException(status_code=404, detail="Aucun logo personnalisé configuré.")
    ext = logo_path.suffix.lower()
    media_type = MIME_TYPES.get(ext, "application/octet-stream")
    return FileResponse(
        path=str(logo_path),
        media_type=media_type,
        filename=logo_path.name,
    )


@router.post("/logo")
async def upload_custom_logo(
    file: UploadFile = File(...),
    _auth=Depends(require_auth),
):
    """Upload un nouveau logo personnalisé (PNG/JPG/SVG/WebP/GIF, max 2 Mo)."""
    # Vérifier l'extension
    original_name = file.filename or "logo.png"
    ext = Path(original_name).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Format non supporté : {ext}. Formats acceptés : {', '.join(ALLOWED_EXTENSIONS)}",
        )

    # Lire et vérifier la taille
    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"Fichier trop volumineux ({len(content) // 1024} Ko). Maximum : {MAX_FILE_SIZE // 1024} Ko.",
        )

    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Le fichier est vide.")

    # S'assurer que data/ existe
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Supprimer les anciens logos
    _cleanup_old_logos()

    # Sauvegarder le nouveau logo
    dest = DATA_DIR / f"custom_logo{ext}"
    dest.write_bytes(content)
    logger.info("Logo personnalisé sauvegardé : %s (%d octets)", dest, len(content))

    return {"ok": True, "message": "Logo mis à jour avec succès.", "filename": dest.name}


@router.delete("/logo")
def delete_custom_logo(_auth=Depends(require_auth)):
    """Supprime le logo personnalisé (retour au logo par défaut SIATI)."""
    logo_path = _find_custom_logo()
    if logo_path is None:
        return {"ok": True, "message": "Aucun logo personnalisé à supprimer."}

    logo_path.unlink()
    logger.info("Logo personnalisé supprimé : %s", logo_path)
    return {"ok": True, "message": "Logo réinitialisé au défaut."}
