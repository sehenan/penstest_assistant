"""
Error Handling Module - Standardized error responses and logging
"""
from typing import Optional, Dict, Any
from fastapi import HTTPException, status, Request
from fastapi.responses import JSONResponse
import logging
import re
import traceback
from datetime import datetime
import json
import os
from pathlib import Path

# Répertoire de logs : surcharge via SIATI_LOGS_DIR, sinon <racine_projet>/logs.
# parents[2] = racine du dépôt (.../penstest_assistant en dev, /app en conteneur),
# pas parents[3] qui pointait un cran trop haut (/ en conteneur -> non inscriptible).
_DEFAULT_LOGS_DIR = Path(__file__).resolve().parents[2] / "logs"
_LOGS_DIR = Path(os.environ.get("SIATI_LOGS_DIR", _DEFAULT_LOGS_DIR))

# Repli gracieux : si le dossier n'est pas inscriptible (FS read-only, droits),
# on bascule sur la console uniquement plutôt que de faire échouer l'import.
_log_handlers = [logging.StreamHandler()]
try:
    os.makedirs(_LOGS_DIR, exist_ok=True)
    _log_handlers.insert(0, logging.FileHandler(str(_LOGS_DIR / 'app.log')))
except OSError:
    pass

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=_log_handlers
)

logger = logging.getLogger(__name__)

class AppError(Exception):
    """Base application error"""

    def __init__(
        self,
        message: str,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        error_code: str = "INTERNAL_ERROR",
        details: Optional[Dict[str, Any]] = None
    ):
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)

class ValidationError(AppError):
    """Validation error"""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            error_code="VALIDATION_ERROR",
            details=details
        )

class NotFoundError(AppError):
    """Resource not found error"""

    def __init__(self, resource: str, identifier: str):
        super().__init__(
            message=f"{resource} not found: {identifier}",
            status_code=status.HTTP_404_NOT_FOUND,
            error_code="NOT_FOUND",
            details={"resource": resource, "identifier": identifier}
        )

class AuthenticationError(AppError):
    """Authentication error"""

    def __init__(self, message: str = "Authentication failed"):
        super().__init__(
            message=message,
            status_code=status.HTTP_401_UNAUTHORIZED,
            error_code="AUTHENTICATION_ERROR"
        )

class AuthorizationError(AppError):
    """Authorization error"""

    def __init__(self, message: str = "Insufficient permissions"):
        super().__init__(
            message=message,
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="AUTHORIZATION_ERROR"
        )

class RateLimitError(AppError):
    """Rate limit exceeded error"""

    def __init__(self, limit: int, window: int):
        super().__init__(
            message=f"Rate limit exceeded: {limit} requests per {window} seconds",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            error_code="RATE_LIMIT_EXCEEDED",
            details={"limit": limit, "window": window}
        )

class ExternalServiceError(AppError):
    """External service error"""

    def __init__(self, service: str, message: str):
        super().__init__(
            message=f"External service error ({service}): {message}",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            error_code="EXTERNAL_SERVICE_ERROR",
            details={"service": service}
        )

class DatabaseError(AppError):
    """Database operation error"""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=f"Database error: {message}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error_code="DATABASE_ERROR",
            details=details
        )

class MLError(AppError):
    """Machine learning model error"""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=f"ML error: {message}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error_code="ML_ERROR",
            details=details
        )

class LLMError(AppError):
    """LLM generation error"""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=f"LLM error: {message}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error_code="LLM_ERROR",
            details=details
        )

def log_error(
    error: Exception,
    request: Optional[Request] = None,
    additional_context: Optional[Dict[str, Any]] = None
):
    """Structured error logging"""

    error_info = {
        "timestamp": datetime.utcnow().isoformat(),
        "error_type": type(error).__name__,
        "error_message": str(error),
        "traceback": traceback.format_exc()
    }

    if request:
        error_info.update({
            "request_method": request.method,
            "request_url": str(request.url),
            "client_ip": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent")
        })

    if isinstance(error, AppError):
        error_info.update({
            "error_code": error.error_code,
            "status_code": error.status_code,
            "details": error.details
        })

    if additional_context:
        error_info.update(additional_context)

    logger.error(json.dumps(error_info, default=str))

async def app_error_handler(request: Request, error: Exception) -> JSONResponse:
    """Global error handler for FastAPI"""

    # Log the error
    log_error(error, request)

    # Handle known application errors
    if isinstance(error, AppError):
        return JSONResponse(
            status_code=error.status_code,
            content={
                "error": {
                    "code": error.error_code,
                    "message": error.message,
                    "details": error.details,
                    "timestamp": datetime.utcnow().isoformat()
                }
            }
        )

    # Handle HTTP exceptions
    if isinstance(error, HTTPException):
        return JSONResponse(
            status_code=error.status_code,
            content={
                "error": {
                    "code": "HTTP_ERROR",
                    "message": error.detail,
                    "timestamp": datetime.utcnow().isoformat()
                }
            }
        )

    # Handle unexpected errors
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An unexpected error occurred",
                "timestamp": datetime.utcnow().isoformat()
            }
        }
    )

def handle_database_error(func):
    """Decorator for database error handling"""

    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            error_msg = str(e)
            if "constraint" in error_msg.lower() or "duplicate" in error_msg.lower():
                raise ValidationError("Duplicate entry", {"original_error": error_msg})
            elif "connection" in error_msg.lower():
                raise DatabaseError("Connection failed", {"original_error": error_msg})
            else:
                raise DatabaseError(error_msg, {"original_error": error_msg})

    return wrapper

def handle_ml_error(func):
    """Decorator for ML error handling"""

    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except FileNotFoundError as e:
            raise MLError("Model file not found", {"file": str(e)})
        except Exception as e:
            raise MLError(str(e), {"original_error": str(e)})

    return wrapper

def handle_llm_error(func):
    """Decorator for LLM error handling"""

    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ConnectionError as e:
            raise LLMError("LLM service unavailable", {"service": "ollama"})
        except TimeoutError as e:
            raise LLMError("LLM request timeout", {"timeout": str(e)})
        except Exception as e:
            raise LLMError(str(e), {"original_error": str(e)})

    return wrapper

def validate_required_fields(data: Dict[str, Any], required_fields: list) -> None:
    """Validate that required fields are present"""

    missing_fields = [field for field in required_fields if field not in data or data[field] is None]

    if missing_fields:
        raise ValidationError(
            f"Missing required fields: {', '.join(missing_fields)}",
            {"missing_fields": missing_fields}
        )

# Bloc <script>…</script> complet (contenu inclus), insensible à la casse et multi-lignes.
_SCRIPT_BLOCK_RE = re.compile(r"<\s*script\b[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL)
# Toute balise HTML résiduelle bien formée, y compris une balise <script> orpheline.
_HTML_TAG_RE = re.compile(r"<[^>]*>")
# Fragment <script … sans '>' de fermeture (ex. « John<script »).
_SCRIPT_FRAGMENT_RE = re.compile(r"<\s*/?\s*script[^>]*", re.IGNORECASE)


def _sanitize_str(value: str, max_length: int) -> str:
    """Tronque puis neutralise le contenu HTML/script d'une chaîne."""
    if len(value) > max_length:
        value = value[:max_length]
    # 1. Retire les blocs <script>...</script> AVEC leur contenu (payload XSS inclus).
    value = _SCRIPT_BLOCK_RE.sub("", value)
    # 2. Retire les balises HTML résiduelles bien formées.
    value = _HTML_TAG_RE.sub("", value)
    # 3. Retire les fragments <script partiels (sans '>' de fermeture).
    value = _SCRIPT_FRAGMENT_RE.sub("", value)
    return value


def _sanitize_value(value: Any, max_length: int) -> Any:
    """Assainit récursivement une valeur, quel que soit son type."""
    if isinstance(value, str):
        return _sanitize_str(value, max_length)
    if isinstance(value, dict):
        return {k: _sanitize_value(v, max_length) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_value(item, max_length) for item in value]
    # Types non textuels (int, bool, None, float…) laissés intacts.
    return value


def sanitize_input(data: Dict[str, Any], max_length: int = 10000) -> Dict[str, Any]:
    """Assainit un dictionnaire d'entrée pour prévenir les injections (XSS/HTML)."""
    return {key: _sanitize_value(value, max_length) for key, value in data.items()}