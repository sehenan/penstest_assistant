"""
Security Module - JWT Authentication and Rate Limiting
"""
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from fastapi import HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from jose import jwt
import redis
from functools import wraps
import time
import asyncio
import inspect

# Configuration
# La clé de signature JWT vient de l'environnement (SECRET_KEY). Le repli en dur
# n'est qu'un défaut de développement local — À NE JAMAIS utiliser en production
# (positionner SECRET_KEY dans .env ou les variables d'environnement du déploiement).
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-insecure-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Mode d'authentification. Par défaut OFF : la plateforme est conçue pour un usage
# LOCAL / air-gap (API liée à 127.0.0.1, mono-utilisateur). Passer SIATI_REQUIRE_AUTH=1
# pour un déploiement réseau : les routes protégées exigeront alors un token valide.
REQUIRE_AUTH = os.environ.get("SIATI_REQUIRE_AUTH", "0").lower() in ("1", "true", "yes", "on")

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT Bearer
security = HTTPBearer()

# Redis client for rate limiting (fallback to in-memory if Redis unavailable)
try:
    redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
    redis_client.ping()
    USE_REDIS = True
except:
    USE_REDIS = False
    # In-memory fallback
    rate_limit_store = {}

class RateLimiter:
    """Rate limiter using Redis or in-memory storage"""

    def __init__(self, redis_client=None, use_redis=True):
        self.redis_client = redis_client
        self.use_redis = use_redis and redis_client is not None
        # Stockage mémoire du fallback (quand Redis est indisponible).
        # Attribut d'instance -> isolation propre entre limiteurs.
        self.memory_store: Dict[str, list] = {}

    def is_allowed(self, key: str, limit: int, window: int) -> bool:
        """
        Check if request is allowed based on rate limit
        key: identifier (ip, user_id, etc.)
        limit: max requests per window
        window: time window in seconds
        """
        current_time = int(time.time())

        if self.use_redis:
            return self._check_redis(key, limit, window, current_time)
        else:
            return self._check_memory(key, limit, window, current_time)

    def _check_redis(self, key: str, limit: int, window: int, current_time: int) -> bool:
        """Redis-based rate limiting"""
        pipe = self.redis_client.pipeline()

        # Remove old entries
        old_time = current_time - window
        pipe.zremrangebyscore(key, 0, old_time)

        # Count current requests
        pipe.zcard(key)

        # Add current request
        pipe.zadd(key, {str(current_time): current_time})

        # Set expiration
        pipe.expire(key, window)

        results = pipe.execute()
        current_count = results[1]

        return current_count < limit

    def _check_memory(self, key: str, limit: int, window: int, current_time: int) -> bool:
        """In-memory rate limiting fallback"""
        if key not in self.memory_store:
            self.memory_store[key] = []

        # Remove old entries
        self.memory_store[key] = [
            timestamp for timestamp in self.memory_store[key]
            if timestamp > current_time - window
        ]

        # Check limit
        if len(self.memory_store[key]) >= limit:
            return False

        # Add current request
        self.memory_store[key].append(current_time)
        return True

# Global rate limiter instance
rate_limiter = RateLimiter(redis_client if USE_REDIS else None, USE_REDIS)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Hash a password"""
    return pwd_context.hash(password)

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt

def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and verify JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired"
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """Get current user from JWT token"""
    token = credentials.credentials
    payload = decode_access_token(token)

    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )

    return {"user_id": user_id, **payload}


# Bearer « souple » : ne lève pas d'erreur automatique quand l'en-tête est absent,
# ce qui permet les modes « public mais validé si présent » ci-dessous.
optional_security = HTTPBearer(auto_error=False)


def verify_token_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(optional_security),
) -> Optional[Dict[str, Any]]:
    """Accès public si AUCUN token n'est fourni ; mais si un token EST fourni, il
    doit être valide (sinon 401). Empêche qu'un jeton falsifié soit silencieusement
    accepté sur les routes de lecture."""
    if credentials is None:
        return None
    return decode_access_token(credentials.credentials)


def require_auth(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(optional_security),
) -> Optional[Dict[str, Any]]:
    """Garde des routes sensibles/destructives.
    - SIATI_REQUIRE_AUTH activé (déploiement réseau) : un token valide est OBLIGATOIRE.
    - Sinon (local/air-gap, défaut) : accès autorisé, mais tout token fourni est validé.
    """
    if credentials is None:
        if REQUIRE_AUTH:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentification requise",
            )
        return None
    return decode_access_token(credentials.credentials)


def rate_limit(limit: int = 100, window: int = 60):
    """
    Rate limiting decorator
    limit: max requests per window
    window: time window in seconds
    """
    def decorator(func):
        # La fonction cible accepte-t-elle un paramètre `request` (ou **kwargs) ?
        # Sinon, on consomme `request` pour le rate-limiting SANS le lui transmettre.
        try:
            _params = inspect.signature(func).parameters
            _func_takes_request = "request" in _params or any(
                p.kind == inspect.Parameter.VAR_KEYWORD for p in _params.values()
            )
        except (ValueError, TypeError):
            _func_takes_request = True

        def check_rate_limit(args, kwargs):
            # Get request from args or kwargs (FastAPI dependency)
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

            if request is None:
                request = kwargs.get('request')

            if request:
                # Use client IP as key
                client_ip = request.client.host
                key = f"rate_limit:{client_ip}"

                if not rate_limiter.is_allowed(key, limit, window):
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=f"Rate limit exceeded: {limit} requests per {window} seconds"
                    )

            # N'expose pas `request` à une fonction qui ne le déclare pas.
            if not _func_takes_request:
                kwargs.pop('request', None)

        if asyncio.iscoroutinefunction(func):
            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                check_rate_limit(args, kwargs)
                return await func(*args, **kwargs)
            return async_wrapper
        else:
            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                check_rate_limit(args, kwargs)
                return func(*args, **kwargs)
            return sync_wrapper

    return decorator

def admin_required(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Check if user has admin privileges"""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user