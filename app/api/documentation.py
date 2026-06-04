"""
API Documentation and OpenAPI Configuration
Complete API documentation with Swagger/OpenAPI specifications
"""
from typing import Dict, Any
from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials


def custom_openapi_schema(app: FastAPI) -> Dict[str, Any]:
    """
    Generate custom OpenAPI schema with enhanced documentation

    Args:
        app: FastAPI application instance

    Returns:
        Complete OpenAPI schema dictionary
    """
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="SIATI API",
        version="2.0.0",
        description="""
        # SIATI - Système Intelligent d'Assistance aux Tests d'Intrusion

        ## Overview
        SIATI est une plateforme moderne de pentesting assisté par IA qui combine :
        - **Machine Learning** pour la priorisation des vulnérabilités
        - **LLM (Ollama)** pour la génération de playbooks d'exploitation
        - **RAG (Retrieval-Augmented Generation)** pour des réponses précises
        - **Analyse de vulnérabilités** en temps réel

        ## Key Features
        - 🎯 **Priorisation ML** : Scoring intelligent des risques
        - 🤖 **Génération LLM** : Playbooks d'audit et d'exploitation
        - 📊 **Monitoring** : Métriques en temps réel
        - 🔒 **Sécurité** : Authentification JWT et rate limiting
        - 🚀 **Performance** : Architecture asynchrone optimisée

        ## Authentication
        La plupart des endpoints nécessitent une authentification via JWT Bearer token.

        ## Rate Limiting
        Les endpoints sont protégés par rate limiting pour prévenir les abus.

        ## Error Handling
        L'API utilise des codes d'erreur HTTP standard avec des réponses JSON structurées.

        ## Support
        Pour toute question technique, consultez la documentation complète.
        """,
        routes=app.routes,
    )

    # Add custom information
    openapi_schema["info"]["contact"] = {
        "name": "SIATI Support",
        "email": "support@siati.example.com",
        "url": "https://siati.example.com"
    }

    openapi_schema["info"]["license"] = {
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT"
    }

    # Add servers configuration
    openapi_schema["servers"] = [
        {
            "url": "http://localhost:8505",
            "description": "Development server"
        },
        {
            "url": "https://api.siati.example.com",
            "description": "Production server"
        }
    ]

    # Add security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "JWT Bearer token authentication"
        }
    }

    # Add common error responses
    openapi_schema["components"]["schemas"]["ErrorResponse"] = {
        "type": "object",
        "properties": {
            "error": {
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "Error code identifier",
                        "example": "VALIDATION_ERROR"
                    },
                    "message": {
                        "type": "string",
                        "description": "Human-readable error message",
                        "example": "Invalid input data"
                    },
                    "details": {
                        "type": "object",
                        "description": "Additional error details",
                        "example": {"field": "email", "reason": "Invalid format"}
                    },
                    "timestamp": {
                        "type": "string",
                        "format": "date-time",
                        "description": "Error timestamp"
                    }
                },
                "required": ["code", "message", "timestamp"]
            }
        }
    }

    # Add common response examples
    openapi_schema["components"]["examples"] = {
        "ValidationError": {
            "summary": "Validation Error Example",
            "value": {
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Invalid input data",
                    "details": {
                        "field": "email",
                        "reason": "Invalid email format"
                    },
                    "timestamp": "2024-12-08T10:30:00Z"
                }
            }
        },
        "NotFoundError": {
            "summary": "Not Found Error Example",
            "value": {
                "error": {
                    "code": "NOT_FOUND",
                    "message": "Vulnerability not found: CVE-2024-1234",
                    "details": {
                        "resource": "Vulnerability",
                        "identifier": "CVE-2024-1234"
                    },
                    "timestamp": "2024-12-08T10:30:00Z"
                }
            }
        },
        "RateLimitError": {
            "summary": "Rate Limit Error Example",
            "value": {
                "error": {
                    "code": "RATE_LIMIT_EXCEEDED",
                    "message": "Rate limit exceeded: 60 requests per 60 seconds",
                    "details": {
                        "limit": 60,
                        "window": 60
                    },
                    "timestamp": "2024-12-08T10:30:00Z"
                }
            }
        }
    }

    # Add tags for better organization
    openapi_schema["tags"] = [
        {
            "name": "Health",
            "description": "Health check and system status endpoints"
        },
        {
            "name": "Authentication",
            "description": "User authentication and token management"
        },
        {
            "name": "Statistics",
            "description": "Global statistics and metrics"
        },
        {
            "name": "Hosts",
            "description": "Host management and information"
        },
        {
            "name": "Services",
            "description": "Service information and management"
        },
        {
            "name": "Vulnerabilities",
            "description": "Vulnerability analysis and management"
        },
        {
            "name": "Reports",
            "description": "Report generation and management"
        },
        {
            "name": "ML Models",
            "description": "Machine learning model management"
        },
        {
            "name": "Playbooks",
            "description": "Playbook generation and management"
        },
        {
            "name": "Knowledge Base",
            "description": "Knowledge base queries and management"
        },
        {
            "name": "Scans",
            "description": "Scan file upload and processing"
        },
        {
            "name": "Bulk Operations",
            "description": "Bulk operations on multiple items"
        },
        {
            "name": "System",
            "description": "System metrics and monitoring"
        }
    ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


# ============================================================================
# API ENDPOINT DOCUMENTATION
# ============================================================================

API_ENDPOINTS_DOCS = {
    "health": {
        "GET /health": {
            "summary": "Health check endpoint",
            "description": "Check if the API and all its dependencies are running properly",
            "responses": {
                "200": {"description": "All systems operational"},
                "503": {"description": "Service unavailable"}
            },
            "tags": ["Health"]
        }
    },
    "auth": {
        "POST /api/auth/login": {
            "summary": "User login",
            "description": "Authenticate user and return JWT token",
            "request_body": {
                "username": "string (required)",
                "password": "string (required, min 8 chars)"
            },
            "responses": {
                "200": {
                    "description": "Login successful",
                    "content": {
                        "access_token": "JWT token",
                        "token_type": "Bearer",
                        "expires_in": "seconds until expiration"
                    }
                },
                "401": {"description": "Invalid credentials"}
            },
            "tags": ["Authentication"]
        },
        "POST /api/auth/refresh": {
            "summary": "Refresh access token",
            "description": "Refresh an expired JWT token",
            "security": [{"BearerAuth": []}],
            "responses": {
                "200": {"description": "Token refreshed successfully"},
                "401": {"description": "Invalid or expired token"}
            },
            "tags": ["Authentication"]
        }
    },
    "stats": {
        "GET /api/stats": {
            "summary": "Get global statistics",
            "description": "Retrieve overall system statistics including vulnerability counts, host information, and severity distribution",
            "responses": {
                "200": {
                    "description": "Statistics retrieved successfully",
                    "content": {
                        "total_vulns": "integer",
                        "total_hosts": "integer",
                        "total_reports": "integer",
                        "avg_cvss": "float",
                        "severity_distribution": "object",
                        "last_scan": "datetime"
                    }
                }
            },
            "tags": ["Statistics"]
        }
    },
    "vulnerabilities": {
        "GET /api/vulns": {
            "summary": "List vulnerabilities",
            "description": "Retrieve paginated list of vulnerabilities with optional filtering",
            "parameters": {
                "severity": "Filter by severity level",
                "source": "Filter by data source",
                "q": "Search query",
                "cvss_min": "Minimum CVSS score",
                "cvss_max": "Maximum CVSS score",
                "has_exploit": "Filter by exploit availability",
                "limit": "Results per page (default: 100)",
                "offset": "Page offset (default: 0)"
            },
            "responses": {
                "200": {"description": "Vulnerabilities retrieved successfully"},
                "400": {"description": "Invalid filter parameters"}
            },
            "tags": ["Vulnerabilities"]
        },
        "GET /api/vulns/{id}": {
            "summary": "Get vulnerability details",
            "description": "Retrieve detailed information about a specific vulnerability",
            "parameters": {
                "id": "Vulnerability ID (path parameter, required)"
            },
            "responses": {
                "200": {"description": "Vulnerability details retrieved successfully"},
                "404": {"description": "Vulnerability not found"}
            },
            "tags": ["Vulnerabilities"]
        }
    },
    "playbooks": {
        "POST /api/playbooks/generate": {
            "summary": "Generate playbook",
            "description": "Generate an audit or exploitation playbook for a specific vulnerability using LLM",
            "security": [{"BearerAuth": []}],
            "request_body": {
                "vuln_id": "integer (required)",
                "mode": "enum: audit|payload (default: audit)",
                "context": "object (optional)",
                "language": "string: fr|en (default: fr)"
            },
            "responses": {
                "200": {
                    "description": "Playbook generated successfully",
                    "content": {
                        "report_id": "integer",
                        "vuln_id": "integer",
                        "stage": "string",
                        "status": "string",
                        "content_preview": "string",
                        "generation_time": "float",
                        "sources_used": "array"
                    }
                },
                "400": {"description": "Invalid request parameters"},
                "404": {"description": "Vulnerability not found"},
                "500": {"description": "LLM generation failed"}
            },
            "tags": ["Playbooks"]
        }
    },
    "scans": {
        "POST /api/scans/upload": {
            "summary": "Upload scan file",
            "description": "Upload and process a vulnerability scan file (Nmap, Nessus, or OpenVAS format)",
            "security": [{"BearerAuth": []}],
            "request_body": {
                "file": "file (required)",
                "scan_type": "enum: nmap|nessus|openvas (required)",
                "description": "string (optional)",
                "tags": "array (optional)"
            },
            "responses": {
                "200": {
                    "description": "Scan file processed successfully",
                    "content": {
                        "scan_id": "integer",
                        "hosts_processed": "integer",
                        "vulnerabilities_found": "integer",
                        "processing_time": "float"
                    }
                },
                "400": {"description": "Invalid file format or parameters"},
                "413": {"description": "File too large"}
            },
            "tags": ["Scans"]
        }
    }
}


# ============================================================================
# ERROR CODES DOCUMENTATION
# ============================================================================

ERROR_CODES = {
    "VALIDATION_ERROR": {
        "http_status": 422,
        "description": "Request validation failed",
        "common_causes": [
            "Missing required fields",
            "Invalid data format",
            "Value out of allowed range"
        ],
        "resolution": "Check request parameters and format"
    },
    "NOT_FOUND": {
        "http_status": 404,
        "description": "Requested resource not found",
        "common_causes": [
            "Invalid ID",
            "Resource deleted",
            "Insufficient permissions"
        ],
        "resolution": "Verify resource ID and permissions"
    },
    "AUTHENTICATION_ERROR": {
        "http_status": 401,
        "description": "Authentication failed",
        "common_causes": [
            "Invalid credentials",
            "Expired token",
            "Missing authentication"
        ],
        "resolution": "Check credentials and obtain new token"
    },
    "AUTHORIZATION_ERROR": {
        "http_status": 403,
        "description": "Insufficient permissions",
        "common_causes": [
            "User lacks required role",
            "Resource access restricted",
            "Action not permitted"
        ],
        "resolution": "Contact administrator for permissions"
    },
    "RATE_LIMIT_EXCEEDED": {
        "http_status": 429,
        "description": "Rate limit exceeded",
        "common_causes": [
            "Too many requests",
            "API quota exceeded",
            "Temporary throttling"
        ],
        "resolution": "Wait and retry with reduced frequency"
    },
    "EXTERNAL_SERVICE_ERROR": {
        "http_status": 503,
        "description": "External service unavailable",
        "common_causes": [
            "LLM service down",
            "Database connection failed",
            "External API timeout"
        ],
        "resolution": "Check service status and retry"
    },
    "DATABASE_ERROR": {
        "http_status": 500,
        "description": "Database operation failed",
        "common_causes": [
            "Connection failed",
            "Query error",
            "Constraint violation"
        ],
        "resolution": "Contact support with error details"
    },
    "ML_ERROR": {
        "http_status": 500,
        "description": "Machine learning operation failed",
        "common_causes": [
            "Model file not found",
            "Prediction failed",
            "Training error"
        ],
        "resolution": "Check model status and contact support"
    },
    "LLM_ERROR": {
        "http_status": 500,
        "description": "LLM generation failed",
        "common_causes": [
            "LLM service unavailable",
            "Generation timeout",
            "Invalid prompt"
        ],
        "resolution": "Check LLM service and retry"
    }
}


# ============================================================================
# USAGE EXAMPLES
# ============================================================================

USAGE_EXAMPLES = {
    "authentication": {
        "login": {
            "curl": 'curl -X POST "http://localhost:8505/api/auth/login" -H "Content-Type: application/json" -d \'{"username": "admin", "password": "secure_password"}\'',
            "python": """
import requests

response = requests.post(
    "http://localhost:8505/api/auth/login",
    json={"username": "admin", "password": "secure_password"}
)
token = response.json()["access_token"]
            """,
            "javascript": """
fetch('http://localhost:8505/api/auth/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
        username: 'admin',
        password: 'secure_password'
    })
})
.then(response => response.json())
.then(data => console.log(data));
            """
        }
    },
    "vulnerabilities": {
        "list": {
            "curl": 'curl -X GET "http://localhost:8505/api/vulns?severity=high&limit=10" -H "Authorization: Bearer YOUR_TOKEN"',
            "python": """
import requests

headers = {"Authorization": f"Bearer {token}"}
params = {"severity": "high", "limit": 10}
response = requests.get(
    "http://localhost:8505/api/vulns",
    headers=headers,
    params=params
)
vulns = response.json()
            """
        }
    },
    "playbooks": {
        "generate": {
            "curl": 'curl -X POST "http://localhost:8505/api/playbooks/generate" -H "Authorization: Bearer YOUR_TOKEN" -H "Content-Type: application/json" -d \'{"vuln_id": 123, "mode": "audit"}\'',
            "python": """
import requests

headers = {"Authorization": f"Bearer {token}"}
data = {"vuln_id": 123, "mode": "audit"}
response = requests.post(
    "http://localhost:8505/api/playbooks/generate",
    headers=headers,
    json=data
)
playbook = response.json()
            """
        }
    }
}


def get_api_documentation() -> Dict[str, Any]:
    """
    Get complete API documentation

    Returns:
        Complete API documentation dictionary
    """
    return {
        "openapi": "3.0.0",
        "info": {
            "title": "SIATI API",
            "version": "2.0.0",
            "description": "Système Intelligent d'Assistance aux Tests d'Intrusion"
        },
        "endpoints": API_ENDPOINTS_DOCS,
        "error_codes": ERROR_CODES,
        "examples": USAGE_EXAMPLES,
        "authentication": {
            "type": "JWT Bearer Token",
            "header": "Authorization: Bearer <token>",
            "expiration": "30 minutes (configurable)"
        },
        "rate_limiting": {
            "default": "60 requests per minute",
            "endpoint_specific": "Varies by endpoint",
            "headers": {
                "X-RateLimit-Limit": "Request limit per window",
                "X-RateLimit-Remaining": "Remaining requests",
                "X-RateLimit-Reset": "Unix timestamp when limit resets"
            }
        }
    }