"""
Database fingerprinting for SQL injection.
"""
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class DatabaseFingerprint:
    """Database fingerprint results"""
    database_type: str
    confidence: float
    version: Optional[str] = None
    evidence: Optional[Dict] = None

class DatabaseFingerprinter:
    """Fingerprint database type and version from SQL injection responses"""
    
    def __init__(self):
        # Version detection patterns
        self.version_patterns = {
            'mysql': [
                (r"(\d+\.\d+\.\d+)[^\d]*MySQL", 0.9),
                (r"MySQL[^\d]*(\d+\.\d+\.\d+)", 0.9),
                (r"MariaDB[^\d]*(\d+\.\d+\.\d+)", 0.9),
                (r"version.*?(\d+\.\d+\.\d+)", 0.7),
            ],
            'postgresql': [
                (r"PostgreSQL[^\d]*(\d+\.\d+(?:\.\d+)?)", 0.9),
                (r"PG.*?(\d+\.\d+(?:\.\d+)?)", 0.8),
                (r"version.*?(\d+\.\d+)", 0.6),
            ],
            'mssql': [
                (r"Microsoft SQL Server[^\d]*(\d+\.\d+\.\d+\.\d+)", 0.9),
                (r"SQL Server[^\d]*(\d+\.\d+)", 0.8),
                (r"Version[^\d]*(\d+\.\d+\.\d+)", 0.7),
            ],
            'oracle': [
                (r"Oracle[^\d]*(\d+\.\d+\.\d+\.\d+)", 0.9),
                (r"Oracle Database.*?(\d+[cg]?\.\d+\.\d+\.\d+)", 0.9),
                (r"PL/SQL.*?(\d+\.\d+\.\d+\.\d+)", 0.8),
            ],
        }
        
        # Database-specific function tests
        self.function_tests = {
            'mysql': [
                ("version()", "SELECT version()"),
                ("@@version", "SELECT @@version"),
                ("user()", "SELECT user()"),
                ("database()", "SELECT database()"),
            ],
            'postgresql': [
                ("version()", "SELECT version()"),
                ("current_user", "SELECT current_user"),
                ("current_database()", "SELECT current_database()"),
            ],
            'mssql': [
                ("@@version", "SELECT @@version"),
                ("user_name()", "SELECT user_name()"),
                ("db_name()", "SELECT db_name()"),
            ],
            'oracle': [
                ("banner", "SELECT banner FROM v$version WHERE rownum=1"),
                ("user", "SELECT user FROM dual"),
            ],
        }
        
        # Error message patterns for each database
        self.error_patterns = {
            'mysql': [
                r"MySQLSyntaxErrorException",
                r"You have an error in your SQL syntax",
                r"check the manual that corresponds to your MySQL server version",
            ],
            'postgresql': [
                r"PostgreSQL.*ERROR",
                r"ERROR:\s*syntax error at or near",
                r"PG::SyntaxError",
            ],
            'mssql': [
                r"Unclosed quotation mark",
                r"Incorrect syntax near",
                r"Microsoft OLE DB Provider for SQL Server",
            ],
            'oracle': [
                r"ORA-[0-9]{5}",
                r"ORA-[0-9]{5}:[^']*",
                r"PLS-[0-9]{5}",
            ],
        }
    
    def fingerprint_from_error(self, error_message: str) -> List[DatabaseFingerprint]:
        """
        Fingerprint database from error messages.
        
        Args:
            error_message: SQL error message
            
        Returns:
            List of DatabaseFingerprint objects
        """
        fingerprints = []
        
        for db_type, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, error_message, re.IGNORECASE):
                    # Extract version if possible
                    version = self._extract_version(error_message, db_type)
                    
                    fingerprint = DatabaseFingerprint(
                        database_type=db_type,
                        confidence=0.8,
                        version=version,
                        evidence={
                            'method': 'error_message',
                            'pattern': pattern,
                            'matched_text': re.search(pattern, error_message, re.IGNORECASE).group(0)
                        }
                    )
                    fingerprints.append(fingerprint)
        
        return fingerprints
    
    def _extract_version(self, text: str, db_type: str) -> Optional[str]:
        """Extract version number from text for specific database."""
        if db_type in self.version_patterns:
            for pattern, _ in self.version_patterns[db_type]:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    return match.group(1)
        return None
    
    def fingerprint_from_function(self, function_result: str, 
                                 function_test: str) -> Optional[DatabaseFingerprint]:
        """
        Fingerprint database from function test results.
        
        Args:
            function_result: Result of function test
            function_test: Function that was tested
            
        Returns:
            DatabaseFingerprint or None
        """
        # Check which database this function belongs to
        for db_type, tests in self.function_tests.items():
            for func_name, func_query in tests:
                if function_test in func_query:
                    # Check if result looks like this database's output
                    if self._matches_db_output_pattern(function_result, db_type):
                        return DatabaseFingerprint(
                            database_type=db_type,
                            confidence=0.9,
                            evidence={
                                'method': 'function_test',
                                'function': function_test,
                                'result_sample': function_result[:100]
                            }
                        )
        
        return None
    
    def _matches_db_output_pattern(self, result: str, db_type: str) -> bool:
        """Check if result matches typical output pattern for database."""
        patterns = {
            'mysql': [
                r"\d+\.\d+\.\d+",  # Version format
                r"root@localhost",  # Common MySQL user
                r"MariaDB",  # MariaDB indicator
            ],
            'postgresql': [
                r"PostgreSQL",
                r"postgres",  # Default user
                r"on x86_64",  # Common in version strings
            ],
            'mssql': [
                r"Microsoft SQL Server",
                r"SQL Server",
                r"Edition:",  # Common in version strings
            ],
            'oracle': [
                r"Oracle",
                r"PL/SQL",
                r"Release",  # Common in version strings
            ],
        }
        
        if db_type in patterns:
            for pattern in patterns[db_type]:
                if re.search(pattern, result, re.IGNORECASE):
                    return True
        
        return False
    
    def fingerprint_from_boolean_tests(self, successful_payloads: List[str],
                                      response_patterns: Dict) -> List[DatabaseFingerprint]:
        """
        Fingerprint database from successful boolean test payloads.
        
        Args:
            successful_payloads: List of payloads that worked
            response_patterns: Patterns in responses
            
        Returns:
            List of DatabaseFingerprint objects
        """
        fingerprints = []
        
        # Check payload patterns
        payload_indicators = {
            'mysql': [
                r"SLEEP\(",
                r"BENCHMARK\(",
                r"IF\(",
                r"ExtractValue\(",
                r"UpdateXML\(",
            ],
            'postgresql': [
                r"pg_sleep\(",
                r"::\w+",  # Type casts
                r"current_date",
            ],
            'mssql': [
                r"WAITFOR DELAY",
                r"CONVERT\(",
                r"CAST\(",
            ],
            'oracle': [
                r"DBMS_\w+\.",
                r"FROM dual",
                r"UTL_",
            ],
        }
        
        # Count matches for each database
        db_scores = {db: 0 for db in payload_indicators.keys()}
        
        for payload in successful_payloads:
            for db_type, patterns in payload_indicators.items():
                for pattern in patterns:
                    if re.search(pattern, payload, re.IGNORECASE):
                        db_scores[db_type] += 1
        
        # Create fingerprints for databases with scores
        total_payloads = len(successful_payloads)
        for db_type, score in db_scores.items():
            if score > 0:
                confidence = min(0.5 + (score / total_payloads * 0.5), 0.9)
                
                fingerprint = DatabaseFingerprint(
                    database_type=db_type,
                    confidence=confidence,
                    evidence={
                        'method': 'payload_pattern',
                        'score': score,
                        'total_payloads': total_payloads
                    }
                )
                fingerprints.append(fingerprint)
        
        # Sort by confidence
        fingerprints.sort(key=lambda x: x.confidence, reverse=True)
        
        return fingerprints
    
    def combine_fingerprints(self, fingerprints: List[DatabaseFingerprint]) -> Optional[DatabaseFingerprint]:
        """
        Combine multiple fingerprints into a single best guess.
        
        Args:
            fingerprints: List of fingerprints to combine
            
        Returns:
            Combined DatabaseFingerprint or None
        """
        if not fingerprints:
            return None
        
        # Group by database type
        db_groups = {}
        for fp in fingerprints:
            if fp.database_type not in db_groups:
                db_groups[fp.database_type] = []
            db_groups[fp.database_type].append(fp)
        
        # Find database with highest average confidence
        best_db = None
        best_avg_confidence = 0.0
        
        for db_type, fps in db_groups.items():
            avg_confidence = sum(fp.confidence for fp in fps) / len(fps)
            
            if avg_confidence > best_avg_confidence:
                best_avg_confidence = avg_confidence
                best_db = db_type
        
        if not best_db:
            return None
        
        # Combine evidence
        combined_evidence = {
            'sources': [],
            'method': 'combined'
        }
        
        version = None
        for fp in db_groups[best_db]:
            if fp.version and not version:
                version = fp.version
            
            if fp.evidence:
                combined_evidence['sources'].append({
                    'method': fp.evidence.get('method', 'unknown'),
                    'confidence': fp.confidence
                })
        
        return DatabaseFingerprint(
            database_type=best_db,
            confidence=best_avg_confidence,
            version=version,
            evidence=combined_evidence
        )

# Test function
def test_fingerprinter():
    """Test the database fingerprinter"""
    fingerprinter = DatabaseFingerprinter()
    
    # Test error message fingerprinting
    test_errors = [
        "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
        "ORA-00933: SQL command not properly ended",
        "ERROR: syntax error at or near \"SELECT\" at character 15",
        "Unclosed quotation mark after the character string 'test'."
    ]
    
    print("Error message fingerprinting:")
    for error in test_errors:
        fps = fingerprinter.fingerprint_from_error(error)
        if fps:
            print(f"  '{error[:50]}...' -> {fps[0].database_type} ({fps[0].confidence:.1f})")
        else:
            print(f"  '{error[:50]}...' -> Unknown")
    
    # Test boolean test fingerprinting
    test_payloads = [
        "' AND SLEEP(5)--",
        "' AND pg_sleep(5)--",
        "' WAITFOR DELAY '00:00:05'--",
        "' AND DBMS_PIPE.RECEIVE_MESSAGE(('a'),5)--"
    ]
    
    print("\nBoolean test fingerprinting:")
    fps = fingerprinter.fingerprint_from_boolean_tests(test_payloads, {})
    for fp in fps:
        print(f"  {fp.database_type}: {fp.confidence:.2f}")
    
    return fingerprinter

if __name__ == "__main__":
    test_fingerprinter()