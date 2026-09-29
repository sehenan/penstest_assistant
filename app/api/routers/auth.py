import os
from typing import Optional
from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel

from app.core.security import (
    rate_limit, verify_password, get_password_hash,
    create_access_token, decode_access_token, optional_security
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

_ADMIN_USER = os.environ.get("VULNFIX_ADMIN_USER", "admin")
_ADMIN_PASSWORD_PLAIN = os.environ.get("VULNFIX_ADMIN_PASSWORD", "admin")
_ADMIN_PASSWORD_HASH = get_password_hash(_ADMIN_PASSWORD_PLAIN)

class LoginRequest(BaseModel):
    username: str
    password: str

@router.post("/login")
@rate_limit(limit=10, window=60)
def auth_login(payload: LoginRequest, request: Request):
    """Authentification : retourne un JWT si les identifiants sont valides."""
    if payload.username != _ADMIN_USER or not verify_password(payload.password, _ADMIN_PASSWORD_HASH):
        raise HTTPException(
            status_code=401,
            detail="Identifiant ou mot de passe incorrect.",
        )
    token = create_access_token(data={"sub": payload.username, "role": "admin"})
    return {"access_token": token, "token_type": "bearer"}

@router.get("/me")
def auth_me(credentials: Optional[HTTPAuthorizationCredentials] = Depends(optional_security)):
    """Vérifie le token et renvoie les infos de l'utilisateur courant."""
    if credentials is None:
        raise HTTPException(status_code=401, detail="Token manquant.")
    payload = decode_access_token(credentials.credentials)
    return {"username": payload.get("sub"), "role": payload.get("role", "user")}
