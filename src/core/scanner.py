"""
Main scanner module for the vulnerability scanner.
"""

import os
import sys
import time
import json
import logging
import subprocess
import threading
import tempfile
import requests
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime

from src.core.crawler import WebCrawler
from src.core.vulnerability_checks import VulnerabilityChecker
from src.ai.analyzer import VulnerabilityAnalyzer

# Configure logging
logger = logging.getLogger(__name__)

class ZAPWrapper:
    """Wrapper for direct ZAP interaction."""
    
    def __init__(self, 
                 zap_path: Optional[str] = None, 
                 port: int = 8080, 
                 api_key: Optional[str] = None):
        """
        Initialize ZAP wrapper.
        
        Args:
            zap_path: Path to ZAP executable (if None, assumes ZAP is in PATH)
            port: Port for ZAP API
            api_key: API key for ZAP (if None, no API key is used)
        """
        self.zap_path = zap_path or self._find_zap_path()
        self.port = port
        self.api_key = api_key
        self.base_url = f"http://localhost:{port}"
        self.api_url = f"{self.base_url}/JSON"
        self.zap_process = None
        
    def _find_zap_path(self) -> str:
        """Find ZAP executable in common locations."""
        # Common ZAP locations
        common_locations = [
            # Linux
            "/usr/bin/zap.sh",
            "/usr/local/bin/zap.sh",
            "/opt/zaproxy/zap.sh",
            # macOS
            "/Applications/OWASP ZAP.app/Contents/Java/zap.sh",
            # Windows
            r"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat",
            r"C:\Program Files (x86)\OWASP\Zed Attack Proxy\zap.bat",
        ]
        
        # Check environment variable
        if "ZAP_PATH" in os.environ:
            return os.environ["ZAP_PATH"]
            
        # Check common locations
        for location in common_locations:
            if os.path.exists(location):
                return location
                
        # Try to find in PATH
        for path_dir in os.environ.get("PATH", "").split(os.pathsep):
            path_candidate = os.path.join(path_dir, "zap.sh")
            if os.path.exists(path_candidate):
                return path_candidate
                
        # Fallback to ZAP command
        return "zap.sh"
    
    def start_zap(self, daemon: bool = True) -> bool:
        """
        Start ZAP as a daemon process.
        
        Args:
            daemon: Whether to run ZAP as a daemon
            
        Returns:
            True if ZAP started successfully, False otherwise
        """
        try:
            cmd = [
                self.zap_path,
                "-daemon" if daemon else "",
                "-port", str(self.port),
                "-silent"
            ]
            
            # Add API key if provided
            if self.api_key:
                cmd.extend(["-config", f"api.key={self.api_key}"])
            
            # Start ZAP process
            logger.info(f"Starting ZAP on port {self.port}")
            self.zap_process = subprocess.Popen(
                [arg for arg in cmd if arg], # Remove empty strings
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait for ZAP to start
            max_retries = 30
            retries = 0
            while retries < max_retries:
                try:
                    response = requests.get(f"{self.api_url}/core/view/version", timeout=2)
                    if response.status_code == 200:
                        logger.info("ZAP started successfully")
                        return True
                except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                    retries += 1
                    time.sleep(1)
            
            logger.error("Failed to start ZAP after multiple retries")
            return False
        except Exception as e:
            logger.error(f"Error starting ZAP: {str(e)}")
            return False
    
    def stop_zap(self) -> bool:
        """
        Stop ZAP daemon.
        
        Returns:
            True if ZAP was stopped successfully, False otherwise
        """
        try:
            # Try to stop ZAP gracefully via API
            params = {"formMethod": "GET"}
            if self.api_key:
                params["apikey"] = self.api_key
                
            requests.get(f"{self.api_url}/core/action/shutdown", params=params)
            
            # Wait for ZAP to stop
            if self.zap_process:
                self.zap_process.wait(timeout=10)
            
            return True
        except Exception as e:
            logger.error(f"Error stopping ZAP: {str(e)}")
            
            # Force kill the process
            if self.zap_process:
                try:
                    self.zap_process.terminate()
                    self.zap_process.wait(timeout=5)
                except:
                    self.zap_process.kill()
                    
            return False
    
    def is_running(self) -> bool:
        """
        Check if ZAP is running.
        
        Returns:
            True if ZAP is running, False otherwise
        """
        try:
            response = requests.get(f"{self.api_url}/core/view/version", timeout=2)
            return response.status_code == 200
        except:
            return False
    
    def spider_scan(self, target_url: str, max_children: Optional[int] = None) -> int:
        """
        Start a spider scan.
        
        Args:
            target_url: URL to scan
            max_children: Maximum number of child URLs to crawl
            
        Returns:
            Scan ID or -1 if failed
        """
        try:
            params = {"url": target_url, "formMethod": "GET"}
            
            if self.api_key:
                params["apikey"] = self.api_key
                
            if max_children:
                params["maxChildren"] = max_children
                
            response = requests.get(f"{self.api_url}/spider/action/scan", params=params)
            data = response.json()
            
            if response.status_code == 200:
                return int(data.get("scan", -1))
            
            logger.error(f"Failed to start spider scan: {data.get('error', 'Unknown error')}")
            return -1
        except Exception as e:
            logger.error(f"Error starting spider scan: {str(e)}")
            return -1
    
    def active_scan(self, target_url: str) -> int:
        """
        Start an active scan.
        
        Args:
            target_url: URL to scan
            
        Returns:
            Scan ID or -1 if failed
        """
        try:
            params = {"url": target_url, "formMethod": "GET"}
            
            if self.api_key:
                params["apikey"] = self.api_key
                
            response = requests.get(f"{self.api_url}/ascan/action/scan", params=params)
            data = response.json()
            
            if response.status_code == 200:
                return int(data.get("scan", -1))
            
            logger.error(f"Failed to start active scan: {data.get('error', 'Unknown error')}")
            return -1
        except Exception as e:
            logger.error(f"Error starting active scan: {str(e)}")
            return -1
    
    def scan_status(self, scan_id: int, scan_type: str = "spider") -> int:
        """
        Get scan status.
        
        Args:
            scan_id: ID of the scan
            scan_type: Type of scan ('spider' or 'ascan')
            
        Returns:
            Percentage complete (0-100) or -1 if failed
        """
        try:
            url = f"{self.api_url}/{scan_type}/view/status"
            params = {"scanId": scan_id, "formMethod": "GET"}
            
            if self.api_key:
                params["apikey"] = self.api_key
                
            response = requests.get(url, params=params)
            data = response.json()
            
            if response.status_code == 200:
                return int(data.get("status", -1))
            
            logger.error(f"Failed to get scan status: {data.get('error', 'Unknown error')}")
            return -1
        except Exception as e:
            logger.error(f"Error getting scan status: {str(e)}")
            return -1
    
    def get_alerts(self, base_url: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get all alerts.
        
        Args:
            base_url: Filter alerts by base URL
            
        Returns:
            List of alerts
        """
        try:
            params = {"formMethod": "GET"}
            
            if self.api_key:
                params["apikey"] = self.api_key
                
            if base_url:
                params["baseurl"] = base_url
                
            response = requests.get(f"{self.api_url}/core/view/alerts", params=params)
            data = response.json()
            
            if response.status_code == 200:
                return data.get("alerts", [])
            
            logger.error(f"Failed to get alerts: {data.get('error', 'Unknown error')}")
            return []
        except Exception as e:
            logger.error(f"Error getting alerts: {str(e)}")
            return []
    
    def generate_report(self, report_type: str = "html", filename: Optional[str] = None) -> Optional[str]:
        """
        Generate a report.
        
        Args:
            report_type: Type of report (html, xml, json)
            filename: Output filename (if None, a temporary file is created)
            
        Returns:
            Path to the report file or None if failed
        """
        try:
            params = {"formMethod": "GET", "format": report_type}
            
            if self.api_key:
                params["apikey"] = self.api_key
                
            response = requests.get(f"{self.api_url}/core/other/htmlreport", params=params)
            
            if response.status_code != 200:
                logger.error(f"Failed to generate report: HTTP {response.status_code}")
                return None
            
            # Save report to file
            if not filename:
                fd, filename = tempfile.mkstemp(suffix=f".{report_type}")
                os.close(fd)
                
            with open(filename, 'wb') as f:
                f.write(response.content)
            
            return filename
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            return None
            
class Scanner:
    """Main vulnerability scanner class."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize scanner with configuration.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.target_url = config.get("target_url", "")
        self.max_depth = config.get("max_depth", 2)
        self.threads = config.get("threads", 4)
        self.timeout = config.get("timeout", 30)
        self.user_agent = config.get("user_agent", "VulnerabilityScannerBot/1.0")
        self.enable_ai = config.get("enable_ai_analysis", True)
        
        # Initialize components
        self.crawler = WebCrawler(
            max_depth=self.max_depth,
            threads=self.threads,
            timeout=self.timeout,
            user_agent=self.user_agent
        )
        
        self.vuln_checker = VulnerabilityChecker()
        
        if self.enable_ai:
            self.analyzer = VulnerabilityAnalyzer()
        
        # Initialize ZAP
        self.zap = ZAPWrapper(
            zap_path=config.get("zap_path"),
            port=config.get("zap_port", 8080),
            api_key=config.get("zap_api_key")
        )
        
        # Progress callback
        self.progress_callback = None
        
    def register_progress_callback(self, callback: Callable[[float, str], None]) -> None:
        """
        Register a callback function for progress updates.
        
        Args:
            callback: Function that takes a progress percentage (0-100) and status message
        """
        self.progress_callback = callback
        
    def _update_progress(self, progress: float, message: str) -> None:
        """
        Update scan progress.
        
        Args:
            progress: Progress percentage (0-100)
            message: Status message
        """
        if self.progress_callback:
            self.progress_callback(progress, message)
        else:
            logger.info(f"Progress: {progress:.1f}% - {message}")
            
    def run_scan(self) -> Dict[str, Any]:
        """
        Run a complete vulnerability scan.
        
        Returns:
            Scan results dictionary
        """
        scan_start_time = time.time()
        
        results = {
            "target_url": self.target_url,
            "scan_time": datetime.now().timestamp(),
            "config": self.config,
            "pages_scanned": 0,
            "vulnerabilities": [],
            "summary": {}
        }
        
        try:
            # Step 1: Start ZAP
            self._update_progress(5, "Starting ZAP")
            if not self.zap.start_zap():
                raise Exception("Failed to start ZAP")
                
            # Step 2: Spider scan
            self._update_progress(10, "Starting web crawler")
            spider_scan_id = self.zap.spider_scan(self.target_url, max_children=self.max_depth * 10)
            
            if spider_scan_id == -1:
                raise Exception("Failed to start spider scan")
                
            # Monitor spider progress
            while True:
                progress = self.zap.scan_status(spider_scan_id, "spider")
                if progress >= 100:
                    break
                    
                self._update_progress(10 + (progress * 0.3), f"Crawling website: {progress}%")
                time.sleep(1)
                
            # Step 3: Active scan
            self._update_progress(40, "Starting vulnerability scan")
            active_scan_id = self.zap.active_scan(self.target_url)
            
            if active_scan_id == -1:
                raise Exception("Failed to start active scan")
                
            # Monitor active scan progress
            while True:
                progress = self.zap.scan_status(active_scan_id, "ascan")
                if progress >= 100:
                    break
                    
                self._update_progress(40 + (progress * 0.4), f"Scanning for vulnerabilities: {progress}%")
                time.sleep(2)
                
            # Step 4: Get alerts (vulnerabilities)
            self._update_progress(85, "Processing vulnerabilities")
            zap_alerts = self.zap.get_alerts(self.target_url)
            
            # Convert ZAP alerts to our vulnerability format
            vulnerabilities = []
            
            for alert in zap_alerts:
                vuln = {
                    "type": alert.get("name", "Unknown"),
                    "url": alert.get("url", ""),
                    "method": alert.get("method", "GET"),
                    "param": alert.get("param", ""),
                    "evidence": alert.get("evidence", ""),
                    "description": alert.get("description", ""),
                    "solution": alert.get("solution", ""),
                    "reference": alert.get("reference", ""),
                    "severity": self._map_risk_to_severity(alert.get("risk", "Info")),
                    "confidence": alert.get("confidence", "Low")
                }
                
                # Map ZAP CWE ID if available
                cwe_id = alert.get("cweid")
                if cwe_id:
                    vuln["cwe_id"] = int(cwe_id)
                    
                vulnerabilities.append(vuln)
            
            # Step 5: Run AI analysis if enabled
            if self.enable_ai and vulnerabilities:
                self._update_progress(90, "Running AI analysis")
                
                # Create page list from ZAP results
                pages = []
                # We would ideally get this from ZAP's site tree, but for simplicity we'll extract from alerts
                unique_urls = set(alert.get("url", "") for alert in zap_alerts)
                for url in unique_urls:
                    pages.append({"url": url, "title": "", "depth": 0})
                    
                # Analyze with AI
                vulnerabilities = self.analyzer.analyze(vulnerabilities, pages)
            
            # Step 6: Finalize results
            self._update_progress(95, "Finalizing results")
            
            # Calculate summary
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            vuln_types = {}
            
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "info").lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
                
                vuln_type = vuln.get("type", "unknown")
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
            results["vulnerabilities"] = vulnerabilities
            results["pages_scanned"] = len(set(v.get("url", "") for v in vulnerabilities))
            results["scan_duration"] = time.time() - scan_start_time
            results["summary"] = {
                "total_vulnerabilities": len(vulnerabilities),
                "severity_counts": severity_counts,
                "vulnerability_types": vuln_types
            }
            
            # Generate ZAP report (for reference)
            report_path = self.zap.generate_report("html")
            if report_path:
                results["zap_report_path"] = report_path
            
            self._update_progress(100, "Scan completed")
            
        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            results["error"] = str(e)
        finally:
            # Always stop ZAP
            self.zap.stop_zap()
            
        return results
    
    def _map_risk_to_severity(self, risk: str) -> str:
        """
        Map ZAP risk levels to our severity levels.
        
        Args:
            risk: ZAP risk level
            
        Returns:
            Our severity level
        """
        risk_map = {
            "High": "high",
            "Medium": "medium", 
            "Low": "low",
            "Informational": "info",
            "Info": "info"
        }
        
        return risk_map.get(risk, "info") 