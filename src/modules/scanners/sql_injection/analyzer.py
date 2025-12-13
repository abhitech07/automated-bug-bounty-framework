"""
Analyzes HTTP responses for SQL injection indicators.
"""
import re
from typing import Dict, List, Optional, Tuple
import difflib
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class ResponseAnalysis:
    """Results of response analysis"""
    is_different: bool
    similarity_score: float
    length_difference: int
    has_sql_errors: bool
    error_messages: List[str]
    has_database_errors: bool
    has_blank_page: bool
    has_time_delay: bool
    response_time_ms: float

class SQLResponseAnalyzer:
    """Analyzes responses for SQL injection indicators"""
    
    def __init__(self):
        self.sql_error_patterns = self._load_sql_error_patterns()
        self.database_error_patterns = self._load_database_error_patterns()
    
    def _load_sql_error_patterns(self) -> List[re.Pattern]:
        """Load SQL error regex patterns"""
        patterns = [
            # Generic SQL errors
            re.compile(r'sql.*error', re.IGNORECASE),
            re.compile(r'syntax.*error', re.IGNORECASE),
            re.compile(r'warning.*sql', re.IGNORECASE),
            
            # MySQL errors
            re.compile(r'mysql.*error', re.IGNORECASE),
            re.compile(r'you have an error in your sql syntax', re.IGNORECASE),
            re.compile(r'mysql_fetch', re.IGNORECASE),
            re.compile(r'mysqli_', re.IGNORECASE),
            re.compile(r'mysql_query', re.IGNORECASE),
            
            # PostgreSQL errors
            re.compile(r'postgresql.*error', re.IGNORECASE),
            re.compile(r'pg_.*error', re.IGNORECASE),
            re.compile(r'psql.*error', re.IGNORECASE),
            
            # MSSQL errors
            re.compile(r'microsoft.*sql.*server', re.IGNORECASE),
            re.compile(r'odbc.*sql.*server', re.IGNORECASE),
            re.compile(r'sqlserver.*error', re.IGNORECASE),
            
            # Oracle errors
            re.compile(r'ora-\d+', re.IGNORECASE),
            re.compile(r'oracle.*error', re.IGNORECASE),
            re.compile(r'pl/sql.*error', re.IGNORECASE),
            
            # SQLite errors
            re.compile(r'sqlite.*error', re.IGNORECASE),
            re.compile(r'sqlite3.*error', re.IGNORECASE),
            
            # Common SQL keywords in errors
            re.compile(r'unclosed quotation mark', re.IGNORECASE),
            re.compile(r'incorrect syntax', re.IGNORECASE),
            re.compile(r'unterminated string', re.IGNORECASE),
            re.compile(r'unmatched parenthesis', re.IGNORECASE),
            re.compile(r'division by zero', re.IGNORECASE),
            re.compile(r'type mismatch', re.IGNORECASE),
            re.compile(r'conversion failed', re.IGNORECASE),
        ]
        return patterns
    
    def _load_database_error_patterns(self) -> List[re.Pattern]:
        """Load database-specific error patterns"""
        patterns = [
            # Database connection errors
            re.compile(r'connection.*failed', re.IGNORECASE),
            re.compile(r'can\'t connect', re.IGNORECASE),
            re.compile(r'access denied', re.IGNORECASE),
            re.compile(r'authentication failed', re.IGNORECASE),
            
            # Database server errors
            re.compile(r'database.*error', re.IGNORECASE),
            re.compile(r'db.*error', re.IGNORECASE),
            re.compile(r'query.*failed', re.IGNORECASE),
            re.compile(r'statement.*failed', re.IGNORECASE),
            
            # Permission errors
            re.compile(r'permission denied', re.IGNORECASE),
            re.compile(r'insufficient privilege', re.IGNORECASE),
            re.compile(r'access violation', re.IGNORECASE),
        ]
        return patterns
    
    def analyze_responses(self, 
                         baseline_response: str, 
                         test_response: str,
                         baseline_time_ms: float = 0.0,
                         test_time_ms: float = 0.0,
                         threshold: float = 0.95) -> ResponseAnalysis:
        """
        Compare two responses and analyze for SQL injection indicators.
        
        Args:
            baseline_response: Original/clean response
            test_response: Response with payload injection
            baseline_time_ms: Baseline response time
            test_time_ms: Test response time
            threshold: Similarity threshold (0-1)
            
        Returns:
            ResponseAnalysis object
        """
        # Calculate similarity
        similarity = self._calculate_similarity(baseline_response, test_response)
        
        # Check for differences
        is_different = similarity < threshold
        
        # Calculate length difference
        length_diff = abs(len(test_response) - len(baseline_response))
        
        # Check for SQL errors
        sql_errors = self._check_sql_errors(test_response)
        
        # Check for database errors
        db_errors = self._check_database_errors(test_response)
        
        # Check for blank/error pages
        has_blank_page = self._is_blank_page(test_response)
        
        # Check for time delay
        has_time_delay = False
        if baseline_time_ms > 0 and test_time_ms > 0:
            # Significant delay (more than 2x)
            has_time_delay = test_time_ms > (baseline_time_ms * 2)
        
        return ResponseAnalysis(
            is_different=is_different,
            similarity_score=similarity,
            length_difference=length_diff,
            has_sql_errors=len(sql_errors) > 0,
            error_messages=sql_errors,
            has_database_errors=len(db_errors) > 0,
            has_blank_page=has_blank_page,
            has_time_delay=has_time_delay,
            response_time_ms=test_time_ms
        )
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity between two texts"""
        if not text1 or not text2:
            return 0.0
        
        # Use difflib for sequence matching
        matcher = difflib.SequenceMatcher(None, text1, text2)
        return matcher.ratio()
    
    def _check_sql_errors(self, text: str) -> List[str]:
        """Check for SQL error messages in text"""
        errors = []
        
        for pattern in self.sql_error_patterns:
            matches = pattern.findall(text)
            if matches:
                # Take unique matches
                for match in set(matches):
                    errors.append(match)
        
        return errors
    
    def _check_database_errors(self, text: str) -> List[str]:
        """Check for database error messages"""
        errors = []
        
        for pattern in self.database_error_patterns:
            matches = pattern.findall(text)
            if matches:
                for match in set(matches):
                    errors.append(match)
        
        return errors
    
    def _is_blank_page(self, text: str) -> bool:
        """Check if page is blank or error page"""
        if not text:
            return True
        
        # Remove whitespace
        stripped = text.strip()
        
        # Check for very short responses
        if len(stripped) < 50:
            return True
        
        # Check for common error indicators
        error_indicators = [
            "404", "not found", "error", "exception",
            "internal server error", "500", "403", "forbidden"
        ]
        
        text_lower = stripped.lower()
        for indicator in error_indicators:
            if indicator in text_lower:
                return True
        
        return False
    
    def extract_database_info(self, text: str) -> Dict[str, str]:
        """
        Extract database information from error messages.
        
        Args:
            text: Response text
            
        Returns:
            Dictionary with database info
        """
        info = {}
        
        # Extract MySQL version
        mysql_version = re.search(r'mysql.*(\d+\.\d+\.\d+)', text, re.IGNORECASE)
        if mysql_version:
            info['database'] = 'MySQL'
            info['version'] = mysql_version.group(1)
        
        # Extract PostgreSQL version
        postgres_version = re.search(r'postgresql.*(\d+\.\d+)', text, re.IGNORECASE)
        if postgres_version:
            info['database'] = 'PostgreSQL'
            info['version'] = postgres_version.group(1)
        
        # Extract MSSQL version
        mssql_version = re.search(r'sql server.*(\d{4})', text, re.IGNORECASE)
        if mssql_version:
            info['database'] = 'MSSQL'
            info['version'] = mssql_version.group(1)
        
        # Extract Oracle version
        oracle_version = re.search(r'oracle.*(\d+\.\d+\.\d+\.\d+)', text, re.IGNORECASE)
        if oracle_version:
            info['database'] = 'Oracle'
            info['version'] = oracle_version.group(1)
        
        # Extract database name
        db_name = re.search(r'database[:\s]+([\w_]+)', text, re.IGNORECASE)
        if db_name:
            info['name'] = db_name.group(1)
        
        # Extract table name
        table_name = re.search(r'table[:\s]+([\w_]+)', text, re.IGNORECASE)
        if table_name:
            info['table'] = table_name.group(1)
        
        # Extract column name
        column_name = re.search(r'column[:\s]+([\w_]+)', text, re.IGNORECASE)
        if column_name:
            info['column'] = column_name.group(1)
        
        return info
    
    def find_payload_reflection(self, payload: str, response: str) -> bool:
        """
        Check if payload is reflected in response.
        
        Args:
            payload: Injected payload
            response: HTTP response
            
        Returns:
            True if payload is reflected
        """
        if not payload or not response:
            return False
        
        # Check exact reflection
        if payload in response:
            return True
        
        # Check with URL encoding variations
        encoded_variations = [
            payload.replace("'", "%27"),
            payload.replace(" ", "%20"),
            payload.replace("\"", "%22"),
            payload.replace("=", "%3D"),
        ]
        
        for encoded in encoded_variations:
            if encoded in response:
                return True
        
        # Check for partial reflection
        payload_parts = re.split(r'[^\w]', payload)
        for part in payload_parts:
            if len(part) > 3 and part in response:  # Avoid small common words
                return True
        
        return False

# Global instance
response_analyzer = SQLResponseAnalyzer()