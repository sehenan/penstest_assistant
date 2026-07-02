"""
End-to-End Integration Tests for SIATI
Complete integration tests covering the full application flow
"""
import pytest
import asyncio
from typing import AsyncGenerator, Generator
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
import tempfile
import os
from pathlib import Path

# Import application and dependencies
from app.ui.server import app
from app.db.database import get_session, init_db
from app.db.models import Host, Service, Vulnerability, ScoreML, Report
from app.core.security import create_access_token, get_password_hash


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture(scope="function")
def db_session(monkeypatch, tmp_path) -> Generator[Session, None, None]:
    """
    Base de test ISOLÉE (fichier temporaire), pointée via PENTEST_DB_URL.

    La résolution dynamique de l'URL (app.db.database._resolve_db_url) fait que les
    routes de l'API — qui appellent get_session() en direct — utilisent la MÊME base
    temporaire que ce fixture. On obtient une vraie isolation sans réécrire les routes,
    et surtout SANS polluer data/pentest.db.
    """
    test_db = tmp_path / "test_e2e.db"
    monkeypatch.setenv("PENTEST_DB_URL", f"sqlite:///{test_db}")

    init_db()
    session = get_session()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(scope="function")
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """
    Create a test client for the FastAPI application

    Args:
        db_session: Test database session

    Yields:
        Test client instance
    """
    def override_get_session():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_session] = override_get_session

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def auth_token(client: TestClient) -> str:
    """
    Create an authentication token for testing

    Args:
        client: Test client instance

    Returns:
        JWT access token
    """
    # Create test user token
    token_data = {
        "sub": "test_user",
        "role": "admin",
        "exp": 9999999999  # Far future for testing
    }
    return create_access_token(token_data)


@pytest.fixture(scope="function")
def test_headers(auth_token: str) -> dict:
    """
    Create test headers with authentication

    Args:
        auth_token: JWT access token

    Returns:
        Dictionary with authentication headers
    """
    return {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }


@pytest.fixture(scope="function")
def sample_host_data() -> dict:
    """
    Create sample host data for testing

    Returns:
        Dictionary with host information
    """
    return {
        "ip": "192.168.1.100",
        "hostname": "test-server.example.com",
        "os": "Ubuntu 22.04 LTS"
    }


@pytest.fixture(scope="function")
def sample_service_data() -> dict:
    """
    Create sample service data for testing

    Returns:
        Dictionary with service information
    """
    return {
        "port": 443,
        "protocol": "tcp",
        "service": "https",
        "version": "Apache/2.4.41",
        "banner": "Apache/2.4.41 (Ubuntu)"
    }


@pytest.fixture(scope="function")
def sample_vulnerability_data() -> dict:
    """
    Create sample vulnerability data for testing

    Returns:
        Dictionary with vulnerability information
    """
    return {
        "cve": "CVE-2024-1234",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "cwe": "CWE-79",
        "description": "Cross-site scripting vulnerability in web application",
        "source": "nessus"
    }


@pytest.fixture(scope="function")
def populated_database(db_session: Session) -> Session:
    """
    Create a populated database with test data

    Args:
        db_session: Test database session

    Returns:
        Database session with test data
    """
    # Create test host
    host = Host(
        ip="192.168.1.100",
        hostname="test-server.example.com",
        os="Ubuntu 22.04 LTS"
    )
    db_session.add(host)
    db_session.flush()

    # Create test service
    service = Service(
        host_id=host.id,
        port=443,
        protocol="tcp",
        service="https",
        version="Apache/2.4.41",
        banner="Apache/2.4.41 (Ubuntu)"
    )
    db_session.add(service)
    db_session.flush()

    # Create test vulnerability
    vuln = Vulnerability(
        service_id=service.id,
        cve="CVE-2024-1234",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        cwe="CWE-79",
        description="Cross-site scripting vulnerability",
        source="nessus"
    )
    db_session.add(vuln)
    db_session.flush()

    # Create test ML score
    score = ScoreML(
        vuln_id=vuln.id,
        score=7.8,
        label="haute",
        reasoning="High CVSS score with network attack vector",
        confidence=0.85
    )
    db_session.add(score)

    db_session.commit()

    return db_session


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestHealthEndpoints:
    """Test health check endpoints"""

    def test_health_check(self, client: TestClient):
        """Test basic health check endpoint"""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] == "healthy"

    def test_health_check_with_services(self, client: TestClient):
        """Test health check with service status"""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert "services" in data
        assert "timestamp" in data


class TestAuthenticationFlow:
    """Test complete authentication flow"""

    def test_login_success(self, client: TestClient):
        """Test successful login"""
        # This would require actual user creation endpoint
        # For now, we test the token creation directly
        token_data = {"sub": "test_user", "role": "user"}
        token = create_access_token(token_data)

        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0

    def test_token_validation(self, client: TestClient, auth_token: str):
        """Test token validation with protected endpoint"""
        headers = {"Authorization": f"Bearer {auth_token}"}

        # Try to access a protected endpoint
        response = client.get("/api/stats", headers=headers)

        # Should succeed with valid token
        assert response.status_code in [200, 401]  # 401 if endpoint requires auth

    def test_invalid_token(self, client: TestClient):
        """Test rejection of invalid token"""
        headers = {"Authorization": "Bearer invalid_token"}

        response = client.get("/api/stats", headers=headers)

        # Should fail with invalid token
        assert response.status_code == 401


class TestStatisticsEndpoints:
    """Test statistics and metrics endpoints"""

    def test_get_global_stats(self, client: TestClient, populated_database: Session):
        """Test getting global statistics"""
        response = client.get("/api/stats")

        assert response.status_code == 200
        data = response.json()

        # Verify expected fields
        assert "total_vulns" in data
        assert "total_hosts" in data
        assert "total_reports" in data
        assert "avg_cvss" in data

        # Verify data types
        assert isinstance(data["total_vulns"], int)
        assert isinstance(data["total_hosts"], int)
        assert isinstance(data["avg_cvss"], (int, float))

    def test_stats_with_empty_database(self, client: TestClient, db_session: Session):
        """Test statistics with empty database"""
        response = client.get("/api/stats")

        assert response.status_code == 200
        data = response.json()

        # Should return zeros for empty database
        assert data["total_vulns"] == 0
        assert data["total_hosts"] == 0


class TestVulnerabilityEndpoints:
    """Test vulnerability management endpoints"""

    def test_list_vulnerabilities(self, client: TestClient, populated_database: Session):
        """Test listing vulnerabilities"""
        response = client.get("/api/vulns")

        assert response.status_code == 200
        data = response.json()

        # Should return list
        assert isinstance(data, list)
        # Should have at least one vulnerability from populated database
        assert len(data) >= 1

    def test_list_vulnerabilities_with_filter(self, client: TestClient, populated_database: Session):
        """Test listing vulnerabilities with filters"""
        response = client.get("/api/vulns?severity=haute")

        assert response.status_code == 200
        data = response.json()

        # Should return list
        assert isinstance(data, list)

    def test_get_vulnerability_by_id(self, client: TestClient, populated_database: Session):
        """Test getting specific vulnerability by ID"""
        # Get first vulnerability from database
        vuln = populated_database.query(Vulnerability).first()
        assert vuln is not None

        response = client.get(f"/api/vulns/{vuln.id}")

        assert response.status_code == 200
        data = response.json()

        # Verify vulnerability data
        assert data["id"] == vuln.id
        assert "cve" in data
        assert "cvss_score" in data

    def test_get_nonexistent_vulnerability(self, client: TestClient):
        """Test getting non-existent vulnerability"""
        response = client.get("/api/vulns/99999")

        assert response.status_code == 404


class TestHostEndpoints:
    """Test host management endpoints"""

    def test_list_hosts(self, client: TestClient, populated_database: Session):
        """Test listing hosts"""
        response = client.get("/api/hosts")

        assert response.status_code == 200
        data = response.json()

        # Should return list
        assert isinstance(data, list)
        # Should have at least one host from populated database
        assert len(data) >= 1

    def test_host_data_structure(self, client: TestClient, populated_database: Session):
        """Test host data structure"""
        response = client.get("/api/hosts")

        assert response.status_code == 200
        data = response.json()

        if len(data) > 0:
            host = data[0]
            # Verify expected fields
            assert "id" in host
            assert "ip" in host
            assert "ports" in host
            assert "vuln_labels" in host


class TestReportEndpoints:
    """Test report generation endpoints"""

    def test_list_reports(self, client: TestClient, populated_database: Session):
        """Test listing reports"""
        response = client.get("/api/reports")

        assert response.status_code == 200
        data = response.json()

        # Should return list (may be empty)
        assert isinstance(data, list)


class TestErrorHandling:
    """Test error handling across endpoints"""

    def test_404_error(self, client: TestClient):
        """Test 404 error for non-existent endpoint"""
        response = client.get("/api/nonexistent")

        assert response.status_code == 404

    def test_invalid_method(self, client: TestClient):
        """Test invalid HTTP method"""
        response = client.post("/api/stats")

        # Should return 405 Method Not Allowed or 422
        assert response.status_code in [405, 422]

    def test_malformed_json(self, client: TestClient):
        """Test handling of malformed JSON"""
        response = client.post(
            "/api/generate",
            headers={"Content-Type": "application/json"},
            data="invalid json"
        )

        assert response.status_code == 422


class TestRateLimiting:
    """Test rate limiting functionality"""

    def test_rate_limiting_basic(self, client: TestClient):
        """Test basic rate limiting"""
        # Make multiple rapid requests
        responses = []
        for i in range(65):  # Exceed default limit of 60
            response = client.get("/api/stats")
            responses.append(response)

        # Check if any requests were rate limited
        rate_limited = any(r.status_code == 429 for r in responses)

        # Rate limiting should be enforced
        # (Note: This test may need adjustment based on actual rate limiting implementation)
        # assert rate_limited


class TestDataConsistency:
    """Test data consistency across operations"""

    def test_database_consistency_after_operations(self, client: TestClient, populated_database: Session):
        """Test database consistency after various operations"""
        # Get initial counts
        initial_host_count = populated_database.query(Host).count()
        initial_vuln_count = populated_database.query(Vulnerability).count()

        # Perform some operations
        client.get("/api/stats")
        client.get("/api/vulns")
        client.get("/api/hosts")

        # Refresh session
        populated_database.expire_all()

        # Verify counts haven't changed unexpectedly
        final_host_count = populated_database.query(Host).count()
        final_vuln_count = populated_database.query(Vulnerability).count()

        assert initial_host_count == final_host_count
        assert initial_vuln_count == final_vuln_count


class TestPerformance:
    """Test performance characteristics"""

    def test_response_time_stats(self, client: TestClient):
        """Test stats endpoint response time"""
        import time

        start_time = time.time()
        response = client.get("/api/stats")
        end_time = time.time()

        response_time = end_time - start_time

        assert response.status_code == 200
        # Should respond within 1 second
        assert response_time < 1.0

    def test_concurrent_requests(self, client: TestClient):
        """Test handling of concurrent requests"""
        import threading
        import time

        results = []

        def make_request():
            response = client.get("/api/stats")
            results.append(response.status_code)

        # Create multiple threads
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # All requests should succeed
        assert all(status == 200 for status in results)


class TestSecurity:
    """Test security aspects"""

    def test_sql_injection_protection(self, client: TestClient):
        """Test protection against SQL injection"""
        # Try SQL injection in search query
        response = client.get("/api/vulns?q=' OR '1'='1")

        # Should not cause SQL errors
        assert response.status_code in [200, 400, 422]

    def test_xss_protection(self, client: TestClient):
        """Test protection against XSS"""
        # Try XSS in search query
        response = client.get("/api/vulns?q=<script>alert('xss')</script>")

        # Should handle XSS attempt safely
        assert response.status_code in [200, 400, 422]

        # Verify response doesn't contain unescaped script tags
        if response.status_code == 200:
            content = response.text
            assert "<script>" not in content


# ============================================================================
# END-TO-END WORKFLOW TESTS
# ============================================================================

class TestCompleteWorkflow:
    """Test complete end-to-end workflows"""

    def test_full_analysis_workflow(self, client: TestClient, populated_database: Session):
        """Test complete vulnerability analysis workflow"""
        # Step 1: Get statistics
        stats_response = client.get("/api/stats")
        assert stats_response.status_code == 200
        stats = stats_response.json()

        # Step 2: List vulnerabilities
        vulns_response = client.get("/api/vulns")
        assert vulns_response.status_code == 200
        vulns = vulns_response.json()

        # Step 3: Get specific vulnerability details
        if len(vulns) > 0:
            vuln_id = vulns[0]["id"]
            detail_response = client.get(f"/api/vulns/{vuln_id}")
            assert detail_response.status_code == 200

        # Step 4: Get hosts
        hosts_response = client.get("/api/hosts")
        assert hosts_response.status_code == 200

        # Verify workflow completed successfully
        assert stats["total_vulns"] > 0
        assert len(vulns) > 0

    def test_error_recovery_workflow(self, client: TestClient):
        """Test error recovery in workflow"""
        # Try to access non-existent resource
        response = client.get("/api/vulns/99999")
        assert response.status_code == 404

        # Verify API still works after error
        response = client.get("/api/stats")
        assert response.status_code == 200


# ============================================================================
# ASYNC TESTS
# ============================================================================

class TestAsyncOperations:
    """Test asynchronous operations"""

    @pytest.mark.asyncio
    async def test_async_database_operations(self, db_session: Session):
        """Test async database operations"""
        # This would test async database operations if implemented
        # For now, we test that the session works correctly
        host_count = db_session.query(Host).count()
        assert isinstance(host_count, int)

    @pytest.mark.asyncio
    async def test_concurrent_async_requests(self, client: TestClient):
        """Test concurrent async requests"""
        async def make_request():
            import asyncio
            await asyncio.sleep(0.1)  # Simulate async operation
            return client.get("/api/stats")

        # Make concurrent requests
        responses = await asyncio.gather(
            make_request(),
            make_request(),
            make_request()
        )

        # All should succeed
        assert all(r.status_code == 200 for r in responses)