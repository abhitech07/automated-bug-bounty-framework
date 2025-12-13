"""
SQL Injection scanning service.
Provides high-level interface for SQL injection detection.
"""
import asyncio
import time
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor
import logging

from .detector import SQLInjectionDetector, SQLInjectionResult
from .boolean_detector import BooleanSQLDetector
from .payloads import DatabaseType, InjectionType
from src.core.database import get_db
from src.core.models import SQLInjectionScan, SQLInjectionVulnerability

logger = logging.getLogger(__name__)

class SQLInjectionService:
    """Service for SQL injection scanning operations"""

    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)

    async def scan_url(self,
                      url: str,
                      scan_id: Optional[str] = None,
                      options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform comprehensive SQL injection scan on a URL.

        Args:
            url: Target URL to scan
            scan_id: Optional scan identifier for tracking
            options: Scan configuration options

        Returns:
            Scan results dictionary
        """
        logger.info(f"Starting SQL injection scan: {url}")

        # Default options
        if options is None:
            options = {}

        scan_options = {
            'timeout': options.get('timeout', 10),
            'max_requests': options.get('max_requests', 100),
            'delay': options.get('delay', 0.5),
            'test_boolean': options.get('test_boolean', True),
            'test_error': options.get('test_error', True),
            'test_time': options.get('test_time', False),  # Time-based can be slow
            'test_union': options.get('test_union', True),
            'db_types': options.get('db_types', ['generic', 'mysql', 'postgresql']),
        }

        start_time = time.time()

        try:
            # Run scan in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(
                self.executor,
                self._perform_scan,
                url,
                scan_options
            )

            scan_duration = time.time() - start_time

            # Save results to database
            saved_results = await self._save_scan_results(
                url=url,
                scan_id=scan_id,
                results=results,
                duration=scan_duration,
                options=scan_options
            )

            logger.info(f"SQL injection scan completed: {len(results.get('vulnerabilities', []))} vulnerabilities found")

            return {
                'scan_id': scan_id,
                'url': url,
                'status': 'completed',
                'duration': scan_duration,
                'vulnerabilities': results.get('vulnerabilities', []),
                'statistics': results.get('statistics', {}),
                'options': scan_options,
            }

        except Exception as e:
            logger.error(f"SQL injection scan failed: {e}")
            return {
                'scan_id': scan_id,
                'url': url,
                'status': 'failed',
                'error': str(e),
                'duration': time.time() - start_time,
            }

    def _perform_scan(self, url: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform the actual scan (runs in thread pool).

        Args:
            url: Target URL
            options: Scan options

        Returns:
            Scan results
        """
        # Initialize detectors
        detector = SQLInjectionDetector(
            timeout=options['timeout'],
            max_requests=options['max_requests'],
            delay=options['delay']
        )

        boolean_detector = BooleanSQLDetector(
            timeout=options['timeout'],
            delay=options['delay']
        )

        vulnerabilities = []
        statistics = {
            'requests_made': 0,
            'parameters_tested': 0,
            'vulnerabilities_found': 0,
        }

        try:
            # Extract parameters from URL
            parameters = detector.extract_parameters(url)

            if not parameters:
                return {
                    'vulnerabilities': [],
                    'statistics': statistics,
                    'message': 'No parameters found in URL'
                }

            logger.info(f"Found {len(parameters)} parameters to test")

            # Test each parameter
            for param in parameters:
                param_name = param['name']
                param_value = param['value']
                param_type = param['type']

                # Test with main detector
                main_findings = detector.test_parameter(
                    url=url,
                    parameter=param_name,
                    original_value=param_value,
                    method='GET' if param_type == 'query' else 'POST',
                    param_type=param_type
                )

                # Convert to dict format
                for finding in main_findings:
                    vulnerabilities.append({
                        'url': finding.url,
                        'parameter': finding.parameter,
                        'payload': finding.payload,
                        'injection_type': finding.injection_type,
                        'database_type': finding.database_type,
                        'confidence': finding.confidence,
                        'evidence': finding.evidence,
                        'method': finding.request.get('method', 'GET'),
                        'detector': 'main',
                    })

                # Test boolean injection if enabled
                if options['test_boolean']:
                    boolean_findings = boolean_detector.test_boolean_injection(
                        url=url,
                        parameter=param_name,
                        original_value=param_value,
                        method='GET' if param_type == 'query' else 'POST',
                        param_type=param_type
                    )

                    for finding in boolean_findings:
                        vulnerabilities.append({
                            'url': url,
                            'parameter': param_name,
                            'payload': f"{finding['true_payload']} / {finding['false_payload']}",
                            'injection_type': 'boolean',
                            'database_type': 'unknown',
                            'confidence': finding['confidence'],
                            'evidence': finding['evidence'],
                            'method': 'GET' if param_type == 'query' else 'POST',
                            'detector': 'boolean',
                        })

            # Update statistics
            statistics['requests_made'] = detector.stats['requests_made']
            statistics['parameters_tested'] = detector.stats['parameters_tested']
            statistics['vulnerabilities_found'] = len(vulnerabilities)

            return {
                'vulnerabilities': vulnerabilities,
                'statistics': statistics,
            }

        except Exception as e:
            logger.error(f"Scan execution failed: {e}")
            return {
                'vulnerabilities': [],
                'statistics': statistics,
                'error': str(e)
            }

    async def _save_scan_results(self,
                               url: str,
                               scan_id: str,
                               results: Dict[str, Any],
                               duration: float,
                               options: Dict[str, Any]) -> bool:
        """
        Save scan results to database.

        Args:
            url: Scanned URL
            scan_id: Scan identifier
            results: Scan results
            duration: Scan duration
            options: Scan options

        Returns:
            True if saved successfully
        """
        try:
            db = next(get_db())

            # Create scan record
            scan_record = SQLInjectionScan(
                scan_id=scan_id,
                url=url,
                status='completed',
                duration=duration,
                options=options,
                statistics=results.get('statistics', {}),
                created_at=time.time()
            )

            db.add(scan_record)
            db.commit()

            # Create vulnerability records
            for vuln in results.get('vulnerabilities', []):
                vuln_record = SQLInjectionVulnerability(
                    scan_id=scan_id,
                    url=vuln['url'],
                    parameter=vuln['parameter'],
                    payload=vuln['payload'],
                    injection_type=vuln['injection_type'],
                    database_type=vuln['database_type'],
                    confidence=vuln['confidence'],
                    evidence=vuln['evidence'],
                    method=vuln.get('method', 'GET'),
                    detector=vuln.get('detector', 'unknown')
                )

                db.add(vuln_record)

            db.commit()
            return True

        except Exception as e:
            logger.error(f"Failed to save scan results: {e}")
            return False

    async def get_scan_results(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve scan results from database.

        Args:
            scan_id: Scan identifier

        Returns:
            Scan results or None if not found
        """
        try:
            db = next(get_db())

            # Get scan record
            scan = db.query(SQLInjectionScan).filter(
                SQLInjectionScan.scan_id == scan_id
            ).first()

            if not scan:
                return None

            # Get vulnerabilities
            vulnerabilities = db.query(SQLInjectionVulnerability).filter(
                SQLInjectionVulnerability.scan_id == scan_id
            ).all()

            # Convert to dict
            vuln_list = []
            for vuln in vulnerabilities:
                vuln_list.append({
                    'id': vuln.id,
                    'url': vuln.url,
                    'parameter': vuln.parameter,
                    'payload': vuln.payload,
                    'injection_type': vuln.injection_type,
                    'database_type': vuln.database_type,
                    'confidence': vuln.confidence,
                    'evidence': vuln.evidence,
                    'method': vuln.method,
                    'detector': vuln.detector,
                    'created_at': vuln.created_at,
                })

            return {
                'scan_id': scan.scan_id,
                'url': scan.url,
                'status': scan.status,
                'duration': scan.duration,
                'options': scan.options,
                'statistics': scan.statistics,
                'vulnerabilities': vuln_list,
                'created_at': scan.created_at,
            }

        except Exception as e:
            logger.error(f"Failed to retrieve scan results: {e}")
            return None

    async def list_scans(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """
        List recent scans.

        Args:
            limit: Maximum number of scans to return
            offset: Offset for pagination

        Returns:
            List of scan summaries
        """
        try:
            db = next(get_db())

            scans = db.query(SQLInjectionScan).order_by(
                SQLInjectionScan.created_at.desc()
            ).limit(limit).offset(offset).all()

            scan_list = []
            for scan in scans:
                scan_list.append({
                    'scan_id': scan.scan_id,
                    'url': scan.url,
                    'status': scan.status,
                    'duration': scan.duration,
                    'vulnerabilities_found': scan.statistics.get('vulnerabilities_found', 0),
                    'created_at': scan.created_at,
                })

            return scan_list

        except Exception as e:
            logger.error(f"Failed to list scans: {e}")
            return []

# Global service instance
sql_injection_service = SQLInjectionService()
