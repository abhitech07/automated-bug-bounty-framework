"""
Integration test for SQLi module with database and API.
"""
import sys
sys.path.insert(0, '.')

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime

from src.main import app
from src.core.database import Base, get_db
from src.core.config import settings

# Test database
TEST_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Override get_db dependency
def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

class TestSQLiIntegration:
    """Test SQLi module integration"""
    
    @classmethod
    def setup_class(cls):
        """Setup test database"""
        Base.metadata.create_all(bind=engine)
    
    @classmethod
    def teardown_class(cls):
        """Cleanup test database"""
        Base.metadata.drop_all(bind=engine)
    
    def test_sqli_api_endpoints(self):
        """Test SQLi API endpoints exist"""
        response = client.get("/api/sqli/test")
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "SQL Injection API is working"
        assert len(data["endpoints"]) > 0
    
    def test_sqli_scan_endpoint(self):
        """Test SQLi scan endpoint"""
        # Test with valid data
        scan_data = {
            "target_url": "http://test.example.com",
            "method": "GET",
            "parameters": {"id": "1"},
            "scan_config": {"max_pages": 10}
        }
        
        response = client.post("/api/sqli/scan", json=scan_data)
        assert response.status_code == 200
        
        data = response.json()
        assert "scan_id" in data
        assert data["status"] == "started"
        assert data["target_url"] == "http://test.example.com"
    
    def test_sqli_scan_validation(self):
        """Test SQLi scan validation"""
        # Test with invalid method
        invalid_data = {
            "target_url": "http://test.example.com",
            "method": "PUT",  # Invalid method
        }
        
        response = client.post("/api/sqli/scan", json=invalid_data)
        assert response.status_code == 422  # Validation error
    
    def test_sqli_statistics_endpoint(self):
        """Test SQLi statistics endpoint"""
        response = client.get("/api/sqli/statistics")
        assert response.status_code == 200
        
        data = response.json()
        assert "total_scans" in data
        assert "completed_scans" in data
        assert "total_findings" in data
        assert isinstance(data["total_scans"], int)
    
    def test_sqli_recent_scans(self):
        """Test recent scans endpoint"""
        response = client.get("/api/sqli/recent-scans?limit=5")
        assert response.status_code == 200
        
        data = response.json()
        assert isinstance(data, list)
    
    def test_sqli_module_integration(self):
        """Test SQLi module integration"""
        response = client.get("/api/test-sqli")
        assert response.status_code == 200
        
        data = response.json()
        assert data["module"] == "sql-injection"
        assert data["status"] == "operational"

def run_integration_tests():
    """Run all integration tests"""
    print("Running SQLi Integration Tests")
    print("=" * 80)
    
    tests = TestSQLiIntegration()
    tests.setup_class()
    
    test_methods = [
        tests.test_sqli_api_endpoints,
        tests.test_sqli_scan_endpoint,
        tests.test_sqli_scan_validation,
        tests.test_sqli_statistics_endpoint,
        tests.test_sqli_recent_scans,
        tests.test_sqli_module_integration,
    ]
    
    results = []
    for test_method in test_methods:
        try:
            test_method()
            results.append(True)
            print(f"✓ {test_method.__name__}: PASSED")
        except Exception as e:
            results.append(False)
            print(f"✗ {test_method.__name__}: FAILED - {e}")
    
    tests.teardown_class()
    
    print("\n" + "=" * 80)
    passed = sum(results)
    total = len(results)
    print(f"SUMMARY: {passed}/{total} tests passed")
    
    if passed == total:
        print("✅ All integration tests passed!")
        return True
    else:
        print("⚠️ Some tests failed. Review the implementation.")
        return False

if __name__ == "__main__":
    success = run_integration_tests()
    sys.exit(0 if success else 1)