"""
Core vulnerability scanner implementation.
"""

import logging
import json
import time
from typing import Dict, List, Any, Optional
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

from src.core.crawler import WebCrawler
from src.core.vulnerability_checks import (
    run_sql_injection_check,
    run_xss_check,
    run_csrf_check,
    run_idor_check,
)
from src.ai.analyzer import VulnerabilityAnalyzer
from src.utils.report_generator import generate_report

logger = logging.getLogger(__name__)

class VulnerabilityScanner:
    """Main vulnerability scanner class that coordinates scanning operations."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the scanner with configuration.
        
        Args:
            config: Dictionary containing scanner configuration
        """
        self.config = config
        self.crawler = WebCrawler(
            max_depth=config.get("crawler", {}).get("max_depth", 3),
            max_pages=config.get("crawler", {}).get("max_pages", 100),
            timeout=config.get("crawler", {}).get("timeout", 10),
            user_agent=config.get("crawler", {}).get("user_agent", "AI-VulScan/1.0")
        )
        self.analyzer = VulnerabilityAnalyzer()
        logger.info("Vulnerability scanner initialized")
    
    def scan(self, target_url: str) -> Dict[str, Any]:
        """
        Perform a vulnerability scan on the target URL.
        
        Args:
            target_url: URL of the target website
            
        Returns:
            Dictionary containing scan results
        """
        logger.info(f"Starting scan on {target_url}")
        start_time = time.time()
        
        # Step 1: Crawl the website
        pages = self.crawler.crawl(target_url)
        logger.info(f"Crawling completed. Found {len(pages)} pages.")
        
        # Step 2: Check for vulnerabilities
        vulnerabilities = self._check_vulnerabilities(target_url, pages)
        
        # Step 3: Analyze vulnerabilities using AI
        analyzed_vulnerabilities = self.analyzer.analyze(vulnerabilities, pages)
        
        # Step 4: Prepare results
        scan_duration = time.time() - start_time
        results = {
            "target_url": target_url,
            "scan_time": start_time,
            "scan_duration": scan_duration,
            "pages_scanned": len(pages),
            "vulnerabilities": analyzed_vulnerabilities,
            "summary": self._generate_summary(analyzed_vulnerabilities)
        }
        
        logger.info(f"Scan completed in {scan_duration:.2f} seconds")
        return results
    
    def _check_vulnerabilities(self, base_url: str, pages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Check for various vulnerabilities in discovered pages.
        
        Args:
            base_url: Base URL of the website
            pages: List of pages discovered during crawling
            
        Returns:
            List of discovered vulnerabilities
        """
        vulnerabilities = []
        
        # Use ThreadPoolExecutor for parallel vulnerability checks
        with ThreadPoolExecutor(max_workers=self.config.get("scanner", {}).get("threads", 5)) as executor:
            # Run SQL injection checks
            sql_futures = [executor.submit(run_sql_injection_check, page) for page in pages]
            # Run XSS checks
            xss_futures = [executor.submit(run_xss_check, page) for page in pages]
            # Run CSRF checks 
            csrf_futures = [executor.submit(run_csrf_check, page) for page in pages]
            # Run IDOR checks
            idor_futures = [executor.submit(run_idor_check, page) for page in pages]
            
            # Collect results
            for future in sql_futures:
                result = future.result()
                if result:
                    vulnerabilities.extend(result)
                    
            for future in xss_futures:
                result = future.result()
                if result:
                    vulnerabilities.extend(result)
                    
            for future in csrf_futures:
                result = future.result()
                if result:
                    vulnerabilities.extend(result)
                    
            for future in idor_futures:
                result = future.result()
                if result:
                    vulnerabilities.extend(result)
        
        logger.info(f"Found {len(vulnerabilities)} potential vulnerabilities")
        return vulnerabilities
    
    def _generate_summary(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a summary of discovered vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerabilities
            
        Returns:
            Summary dictionary
        """
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        vuln_types = {}
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "info").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            vuln_type = vuln.get("type", "unknown")
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        return {
            "total_vulnerabilities": len(vulnerabilities),
            "severity_counts": severity_counts,
            "vulnerability_types": vuln_types
        }
    
    def save_results(self, results: Dict[str, Any], output_file: str) -> None:
        """
        Save scan results to a file.
        
        Args:
            results: Scan results dictionary
            output_file: Path to output file
        """
        file_ext = output_file.split(".")[-1].lower()
        
        if file_ext == "json":
            with open(output_file, "w") as f:
                json.dump(results, f, indent=2)
        else:
            # Generate HTML/PDF report
            generate_report(results, output_file)
        
        logger.info(f"Results saved to {output_file}") 