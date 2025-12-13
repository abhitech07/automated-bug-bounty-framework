#!/usr/bin/env python3
"""Day 1 tests for SQL injection module"""
import sys
sys.path.insert(0, '.')

from src.modules.scanners.sql_injection.payloads import SQLPayloadGenerator
from src.modules.scanners.sql_injection.analyzer import SQLResponseAnalyzer

def test_payload_generator():
    """Test payload generator"""
    print("Testing SQL payload generator...")
    
    generator = SQLPayloadGenerator()
    
    # Test getting payloads
    print("\n1. Testing payload retrieval:")
    
    # Get generic boolean payloads
    bool_payloads = generator.get_payloads(limit=3)
    print(f"   Generic payloads (first 3): {bool_payloads}")
    
    # Get MySQL error payloads
    mysql_errors = generator.get_payloads(
        db_type=generator.database_type.MYSQL,
        injection_type=generator.injection_type.ERROR,
        limit=2
    )
    print(f"   MySQL error payloads: {mysql_errors}")
    
    # Test contextual payload generation
    print("\n2. Testing contextual payloads:")
    context_payload = generator.generate_contextual_payload(
        original_value="123",
        db_type=generator.database_type.MYSQL,
        injection_type=generator.injection_type.BOOLEAN
    )
    print(f"   Contextual payload for '123': {context_payload}")
    
    # Test database detection
    print("\n3. Testing database detection:")
    test_error = "MySQL error: You have an error in your SQL syntax"
    db_type = generator.detect_database_type(test_error)
    print(f"   Detected from '{test_error[:30]}...': {db_type}")
    
    return len(bool_payloads) > 0

def test_response_analyzer():
    """Test response analyzer"""
    print("\nTesting SQL response analyzer...")
    
    analyzer = SQLResponseAnalyzer()
    
    # Test error detection
    print("\n1. Testing error detection:")
    
    test_responses = [
        "MySQL error: Syntax error near 'test'",
        "PostgreSQL: division by zero",
        "ORA-12514: TNS:listener does not currently know of service requested in connect descriptor",
        "No errors here, just normal text",
    ]
    
    for response in test_responses:
        errors = analyzer._check_sql_errors(response)
        print(f"   '{response[:30]}...': {len(errors)} SQL errors")
    
    # Test similarity calculation
    print("\n2. Testing similarity calculation:")
    text1 = "Hello world this is a test"
    text2 = "Hello world this is another test"
    similarity = analyzer._calculate_similarity(text1, text2)
    print(f"   Similarity between texts: {similarity:.2f}")
    
    # Test database info extraction
    print("\n3. Testing database info extraction:")
    error_text = "MySQL error 5.7.34: Table 'test.users' doesn't exist"
    info = analyzer.extract_database_info(error_text)
    print(f"   Extracted info: {info}")
    
    return True

if __name__ == "__main__":
    print("Day 1: SQL Injection Foundation Tests")
    print("=" * 60)
    
    test1 = test_payload_generator()
    test2 = test_response_analyzer()
    
    if test1 and test2:
        print("\n" + "=" * 60)
        print("✅ Day 1 tests passed!")
        print("=" * 60)
        print("\nNext: Implement Boolean-based detection in Day 2")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed")
        sys.exit(1)