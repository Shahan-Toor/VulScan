"""
Database manager for storing and retrieving vulnerability scan results.
"""

import os
import json
import sqlite3
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Database manager for vulnerability scan results."""
    
    def __init__(self, db_path: str = None):
        """
        Initialize the database manager.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path or os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "vulnscan.db")
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        self._init_db()
        logger.info(f"Database initialized at {self.db_path}")
    
    def _init_db(self) -> None:
        """Initialize the database schema if it doesn't exist."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create scans table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                scan_time TIMESTAMP NOT NULL,
                scan_duration REAL,
                pages_scanned INTEGER,
                total_vulnerabilities INTEGER,
                scan_status TEXT,
                config TEXT,
                UNIQUE(target_url, scan_time)
            )
            ''')
            
            # Create vulnerabilities table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                type TEXT NOT NULL,
                url TEXT NOT NULL,
                method TEXT,
                param TEXT,
                payload TEXT,
                evidence TEXT,
                severity TEXT,
                risk_score REAL,
                risk_level TEXT,
                page_title TEXT,
                details TEXT,
                recommendation TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
            ''')
            
            conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Database initialization error: {str(e)}")
        finally:
            if conn:
                conn.close()
    
    def save_scan_results(self, scan_results: Dict[str, Any]) -> int:
        """
        Save scan results to the database.
        
        Args:
            scan_results: Scan results dictionary
            
        Returns:
            ID of the saved scan
        """
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Extract scan information
            target_url = scan_results.get("target_url", "")
            scan_time = scan_results.get("scan_time", datetime.now().timestamp())
            scan_duration = scan_results.get("scan_duration", 0)
            pages_scanned = scan_results.get("pages_scanned", 0)
            
            summary = scan_results.get("summary", {})
            total_vulnerabilities = summary.get("total_vulnerabilities", 0)
            
            # Convert config to JSON if present
            config = scan_results.get("config", {})
            config_json = json.dumps(config) if config else None
            
            # Insert scan record
            cursor.execute('''
            INSERT INTO scans (target_url, scan_time, scan_duration, pages_scanned, 
                              total_vulnerabilities, scan_status, config)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (target_url, scan_time, scan_duration, pages_scanned, 
                 total_vulnerabilities, "completed", config_json))
            
            scan_id = cursor.lastrowid
            
            # Insert vulnerabilities
            vulnerabilities = scan_results.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                vuln_type = vuln.get("type", "unknown")
                url = vuln.get("url", "")
                method = vuln.get("method", "GET")
                param = vuln.get("param", "")
                payload = vuln.get("payload", "")
                evidence = vuln.get("evidence", "")
                severity = vuln.get("severity", "medium")
                risk_score = vuln.get("risk_score", 0.0)
                risk_level = vuln.get("risk_level", severity)
                page_title = vuln.get("page_title", "")
                
                # Convert complex data to JSON
                details = {k: v for k, v in vuln.items() if k not in [
                    "type", "url", "method", "param", "payload", "evidence", 
                    "severity", "risk_score", "risk_level", "page_title", "recommendation"
                ]}
                details_json = json.dumps(details) if details else None
                
                # Convert recommendation to JSON
                recommendation = vuln.get("recommendation", {})
                recommendation_json = json.dumps(recommendation) if recommendation else None
                
                cursor.execute('''
                INSERT INTO vulnerabilities (scan_id, type, url, method, param, payload,
                                           evidence, severity, risk_score, risk_level, 
                                           page_title, details, recommendation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (scan_id, vuln_type, url, method, param, payload, evidence, 
                     severity, risk_score, risk_level, page_title, details_json, 
                     recommendation_json))
            
            conn.commit()
            logger.info(f"Saved scan results for {target_url} with {total_vulnerabilities} vulnerabilities")
            
            return scan_id
            
        except sqlite3.Error as e:
            logger.error(f"Error saving scan results: {str(e)}")
            if conn:
                conn.rollback()
            return -1
        finally:
            if conn:
                conn.close()
    
    def get_scan_history(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Get scan history.
        
        Args:
            limit: Maximum number of records to return
            offset: Offset for pagination
            
        Returns:
            List of scan records
        """
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT id, target_url, scan_time, scan_duration, pages_scanned, 
                  total_vulnerabilities, scan_status
            FROM scans
            ORDER BY scan_time DESC
            LIMIT ? OFFSET ?
            ''', (limit, offset))
            
            rows = cursor.fetchall()
            
            return [dict(row) for row in rows]
            
        except sqlite3.Error as e:
            logger.error(f"Error retrieving scan history: {str(e)}")
            return []
        finally:
            if conn:
                conn.close()
    
    def get_scan_details(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """
        Get detailed information for a specific scan.
        
        Args:
            scan_id: ID of the scan
            
        Returns:
            Scan details dictionary or None if not found
        """
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get scan information
            cursor.execute('''
            SELECT id, target_url, scan_time, scan_duration, pages_scanned, 
                  total_vulnerabilities, scan_status, config
            FROM scans
            WHERE id = ?
            ''', (scan_id,))
            
            row = cursor.fetchone()
            if not row:
                return None
                
            scan_details = dict(row)
            
            # Parse config JSON
            if scan_details.get("config"):
                try:
                    scan_details["config"] = json.loads(scan_details["config"])
                except json.JSONDecodeError:
                    scan_details["config"] = {}
            
            # Get vulnerabilities
            cursor.execute('''
            SELECT id, type, url, method, param, payload, evidence, severity, 
                  risk_score, risk_level, page_title, details, recommendation
            FROM vulnerabilities
            WHERE scan_id = ?
            ORDER BY risk_score DESC
            ''', (scan_id,))
            
            vulnerabilities = []
            for row in cursor.fetchall():
                vuln = dict(row)
                
                # Parse details JSON
                if vuln.get("details"):
                    try:
                        vuln["details"] = json.loads(vuln["details"])
                    except json.JSONDecodeError:
                        vuln["details"] = {}
                
                # Parse recommendation JSON
                if vuln.get("recommendation"):
                    try:
                        vuln["recommendation"] = json.loads(vuln["recommendation"])
                    except json.JSONDecodeError:
                        vuln["recommendation"] = {}
                
                vulnerabilities.append(vuln)
            
            scan_details["vulnerabilities"] = vulnerabilities
            
            # Calculate summary information
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            vuln_types = {}
            
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "info").lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
                
                vuln_type = vuln.get("type", "unknown")
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
            scan_details["summary"] = {
                "total_vulnerabilities": len(vulnerabilities),
                "severity_counts": severity_counts,
                "vulnerability_types": vuln_types
            }
            
            return scan_details
            
        except sqlite3.Error as e:
            logger.error(f"Error retrieving scan details: {str(e)}")
            return None
        finally:
            if conn:
                conn.close()
    
    def delete_scan(self, scan_id: int) -> bool:
        """
        Delete a scan and its vulnerabilities.
        
        Args:
            scan_id: ID of the scan to delete
            
        Returns:
            True if successful, False otherwise
        """
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if scan exists
            cursor.execute("SELECT id FROM scans WHERE id = ?", (scan_id,))
            if not cursor.fetchone():
                logger.warning(f"Attempted to delete non-existent scan with ID {scan_id}")
                return False
            
            # Delete vulnerabilities (should cascade, but just to be safe)
            cursor.execute("DELETE FROM vulnerabilities WHERE scan_id = ?", (scan_id,))
            
            # Delete scan
            cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            
            conn.commit()
            logger.info(f"Deleted scan with ID {scan_id}")
            return True
            
        except sqlite3.Error as e:
            logger.error(f"Error deleting scan: {str(e)}")
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                conn.close()
    
    def search_vulnerabilities(self, 
                              vuln_type: Optional[str] = None,
                              severity: Optional[str] = None,
                              url_pattern: Optional[str] = None,
                              limit: int = 100) -> List[Dict[str, Any]]:
        """
        Search for vulnerabilities with filters.
        
        Args:
            vuln_type: Filter by vulnerability type
            severity: Filter by severity level
            url_pattern: Filter by URL pattern
            limit: Maximum number of results
            
        Returns:
            List of matching vulnerabilities
        """
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Build query
            query = '''
            SELECT v.id, v.type, v.url, v.method, v.param, v.severity, 
                  v.risk_score, v.risk_level, s.target_url as scan_target, s.id as scan_id
            FROM vulnerabilities v
            JOIN scans s ON v.scan_id = s.id
            WHERE 1=1
            '''
            
            params = []
            
            if vuln_type:
                query += " AND v.type = ?"
                params.append(vuln_type)
                
            if severity:
                query += " AND v.severity = ?"
                params.append(severity)
                
            if url_pattern:
                query += " AND v.url LIKE ?"
                params.append(f"%{url_pattern}%")
            
            query += " ORDER BY v.risk_score DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            
            return [dict(row) for row in cursor.fetchall()]
            
        except sqlite3.Error as e:
            logger.error(f"Error searching vulnerabilities: {str(e)}")
            return []
        finally:
            if conn:
                conn.close()
                
    def get_scan_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about all scans.
        
        Returns:
            Dictionary with statistics
        """
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Total scans
            cursor.execute("SELECT COUNT(*) FROM scans")
            total_scans = cursor.fetchone()[0]
            
            # Total vulnerabilities
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
            total_vulnerabilities = cursor.fetchone()[0]
            
            # Vulnerabilities by type
            cursor.execute("""
            SELECT type, COUNT(*) as count
            FROM vulnerabilities
            GROUP BY type
            ORDER BY count DESC
            """)
            vuln_by_type = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Vulnerabilities by severity
            cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM vulnerabilities
            GROUP BY severity
            ORDER BY count DESC
            """)
            vuln_by_severity = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Recent scans
            cursor.execute("""
            SELECT target_url, scan_time, total_vulnerabilities
            FROM scans
            ORDER BY scan_time DESC
            LIMIT 5
            """)
            recent_scans = [{"target": row[0], "time": row[1], "vulnerabilities": row[2]} 
                           for row in cursor.fetchall()]
            
            return {
                "total_scans": total_scans,
                "total_vulnerabilities": total_vulnerabilities,
                "vulnerabilities_by_type": vuln_by_type,
                "vulnerabilities_by_severity": vuln_by_severity,
                "recent_scans": recent_scans
            }
            
        except sqlite3.Error as e:
            logger.error(f"Error getting scan statistics: {str(e)}")
            return {
                "total_scans": 0,
                "total_vulnerabilities": 0,
                "vulnerabilities_by_type": {},
                "vulnerabilities_by_severity": {},
                "recent_scans": []
            }
        finally:
            if conn:
                conn.close() 