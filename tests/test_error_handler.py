"""
Unit Tests for Error Handler Module
"""
import pytest
from fastapi import HTTPException, Request
from unittest.mock import Mock
from app.core.error_handler import (
    AppError, ValidationError, NotFoundError, AuthenticationError,
    AuthorizationError, RateLimitError, ExternalServiceError,
    DatabaseError, MLError, LLMError, validate_required_fields,
    sanitize_input, handle_database_error, handle_ml_error, handle_llm_error
)

class TestCustomErrors:
    """Test custom error classes"""

    def test_app_error_basic(self):
        """Test basic AppError"""
        error = AppError("Test error message")

        assert error.message == "Test error message"
        assert error.status_code == 500
        assert error.error_code == "INTERNAL_ERROR"

    def test_validation_error(self):
        """Test ValidationError"""
        error = ValidationError("Invalid input", {"field": "email"})

        assert error.message == "Invalid input"
        assert error.status_code == 422
        assert error.error_code == "VALIDATION_ERROR"
        assert error.details == {"field": "email"}

    def test_not_found_error(self):
        """Test NotFoundError"""
        error = NotFoundError("User", "123")

        assert error.status_code == 404
        assert error.error_code == "NOT_FOUND"
        assert "User not found" in error.message
        assert error.details["resource"] == "User"
        assert error.details["identifier"] == "123"

    def test_authentication_error(self):
        """Test AuthenticationError"""
        error = AuthenticationError("Invalid credentials")

        assert error.status_code == 401
        assert error.error_code == "AUTHENTICATION_ERROR"
        assert error.message == "Invalid credentials"

    def test_authorization_error(self):
        """Test AuthorizationError"""
        error = AuthorizationError()

        assert error.status_code == 403
        assert error.error_code == "AUTHORIZATION_ERROR"

    def test_rate_limit_error(self):
        """Test RateLimitError"""
        error = RateLimitError(limit=100, window=60)

        assert error.status_code == 429
        assert error.error_code == "RATE_LIMIT_EXCEEDED"
        assert error.details["limit"] == 100
        assert error.details["window"] == 60

    def test_external_service_error(self):
        """Test ExternalServiceError"""
        error = ExternalServiceError("Ollama", "Connection timeout")

        assert error.status_code == 503
        assert error.error_code == "EXTERNAL_SERVICE_ERROR"
        assert error.details["service"] == "Ollama"

    def test_database_error(self):
        """Test DatabaseError"""
        error = DatabaseError("Connection failed")

        assert error.status_code == 500
        assert error.error_code == "DATABASE_ERROR"

    def test_ml_error(self):
        """Test MLError"""
        error = MLError("Model loading failed")

        assert error.status_code == 500
        assert error.error_code == "ML_ERROR"

    def test_llm_error(self):
        """Test LLMError"""
        error = LLMError("Generation timeout")

        assert error.status_code == 500
        assert error.error_code == "LLM_ERROR"

class TestValidationFunctions:
    """Test validation utility functions"""

    def test_validate_required_fields_success(self):
        """Test successful validation of required fields"""
        data = {"name": "John", "email": "john@example.com"}
        required_fields = ["name", "email"]

        # Should not raise any exception
        validate_required_fields(data, required_fields)

    def test_validate_required_fields_missing(self):
        """Test validation with missing required fields"""
        data = {"name": "John"}
        required_fields = ["name", "email"]

        with pytest.raises(ValidationError) as exc_info:
            validate_required_fields(data, required_fields)

        assert "Missing required fields" in str(exc_info.value.message)
        assert "email" in exc_info.value.details["missing_fields"]

    def test_validate_required_fields_none_value(self):
        """Test validation with None values"""
        data = {"name": "John", "email": None}
        required_fields = ["name", "email"]

        with pytest.raises(ValidationError) as exc_info:
            validate_required_fields(data, required_fields)

        assert "email" in exc_info.value.details["missing_fields"]

class TestSanitization:
    """Test input sanitization"""

    def test_sanitize_string(self):
        """Test string sanitization"""
        data = {"name": "John<script>alert('xss')</script>"}
        sanitized = sanitize_input(data)

        assert "<script>" not in sanitized["name"]
        assert "alert('xss')" not in sanitized["name"]

    def test_sanitize_long_string(self):
        """Test truncation of long strings"""
        long_string = "a" * 20000
        data = {"description": long_string}
        sanitized = sanitize_input(data, max_length=100)

        assert len(sanitized["description"]) == 100

    def test_sanitize_nested_dict(self):
        """Test sanitization of nested dictionaries"""
        data = {
            "user": {
                "name": "John<script>",
                "email": "john@example.com"
            }
        }
        sanitized = sanitize_input(data)

        assert "<script>" not in sanitized["user"]["name"]

    def test_sanitize_list(self):
        """Test sanitization of lists"""
        data = {
            "tags": ["tag1<script>", "tag2", "tag3<script>"]
        }
        sanitized = sanitize_input(data)

        assert "<script>" not in sanitized["tags"][0]
        assert "<script>" not in sanitized["tags"][2]

    def test_sanitize_mixed_types(self):
        """Test sanitization with mixed data types"""
        data = {
            "name": "John",
            "age": 30,
            "active": True,
            "tags": ["tag1", "tag2"],
            "metadata": {"key": "value<script>"}
        }
        sanitized = sanitize_input(data)

        assert sanitized["name"] == "John"
        assert sanitized["age"] == 30
        assert sanitized["active"] is True
        assert len(sanitized["tags"]) == 2
        assert "<script>" not in sanitized["metadata"]["key"]

class TestErrorDecorators:
    """Test error handling decorators"""

    def test_handle_database_error_success(self):
        """Test database error decorator with successful operation"""
        @handle_database_error
        def db_operation():
            return "success"

        result = db_operation()
        assert result == "success"

    def test_handle_database_error_constraint(self):
        """Test database error decorator with constraint violation"""
        @handle_database_error
        def db_operation():
            raise Exception("UNIQUE constraint failed")

        with pytest.raises(ValidationError) as exc_info:
            db_operation()

        assert exc_info.value.error_code == "VALIDATION_ERROR"

    def test_handle_database_error_connection(self):
        """Test database error decorator with connection error"""
        @handle_database_error
        def db_operation():
            raise Exception("Connection failed")

        with pytest.raises(DatabaseError) as exc_info:
            db_operation()

        assert exc_info.value.error_code == "DATABASE_ERROR"

    def test_handle_ml_error_file_not_found(self):
        """Test ML error decorator with file not found"""
        @handle_ml_error
        def ml_operation():
            raise FileNotFoundError("model.joblib")

        with pytest.raises(MLError) as exc_info:
            ml_operation()

        assert "Model file not found" in str(exc_info.value.message)

    def test_handle_ml_error_generic(self):
        """Test ML error decorator with generic error"""
        @handle_ml_error
        def ml_operation():
            raise Exception("Prediction failed")

        with pytest.raises(MLError) as exc_info:
            ml_operation()

        assert exc_info.value.error_code == "ML_ERROR"

    def test_handle_llm_error_connection(self):
        """Test LLM error decorator with connection error"""
        @handle_llm_error
        def llm_operation():
            raise ConnectionError("Cannot connect to Ollama")

        with pytest.raises(LLMError) as exc_info:
            llm_operation()

        assert "LLM service unavailable" in str(exc_info.value.message)

    def test_handle_llm_error_timeout(self):
        """Test LLM error decorator with timeout"""
        @handle_llm_error
        def llm_operation():
            raise TimeoutError("Request timeout")

        with pytest.raises(LLMError) as exc_info:
            llm_operation()

        assert "LLM request timeout" in str(exc_info.value.message)

class TestErrorIntegration:
    """Integration tests for error handling"""

    def test_error_flow_with_validation(self):
        """Test complete error flow with validation"""
        # Simulate user input
        user_input = {"name": "John", "email": None}

        # Validate
        with pytest.raises(ValidationError) as exc_info:
            validate_required_fields(user_input, ["name", "email"])

        # Check error details
        assert exc_info.value.status_code == 422
        assert "email" in exc_info.value.details["missing_fields"]

    def test_error_flow_with_sanitization(self):
        """Test complete error flow with sanitization"""
        # Simulate malicious input
        malicious_input = {
            "name": "John<script>alert('xss')</script>",
            "description": "A" * 20000  # Very long string
        }

        # Sanitize
        sanitized = sanitize_input(malicious_input, max_length=100)

        # Verify sanitization
        assert "<script>" not in sanitized["name"]
        assert len(sanitized["description"]) == 100

    def test_error_flow_with_decorators(self):
        """Test complete error flow with decorators"""
        @handle_database_error
        @handle_ml_error
        def complex_operation(data):
            # Simulate validation
            validate_required_fields(data, ["id"])

            # Simulate database operation
            if data.get("id") == "invalid":
                raise Exception("Invalid ID")

            return {"status": "success"}

        # Test successful case
        result = complex_operation({"id": "123"})
        assert result["status"] == "success"

        # Test error case
        with pytest.raises(DatabaseError):
            complex_operation({"id": "invalid"})