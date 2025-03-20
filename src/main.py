#!/usr/bin/env python3
"""
Main entry point for the AI-Enhanced Web Vulnerability Scanner.
"""

import os
import sys
import argparse
import logging
from datetime import datetime

# Add the src directory to the path so we can import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.scanner import Scanner
from src.utils.config import load_config
from src.web.server import start_server

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(f"logs/scanner_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="AI-Enhanced Web Vulnerability Scanner")
    parser.add_argument("--url", type=str, help="Target URL to scan")
    parser.add_argument("--config", type=str, default="config.json", help="Path to configuration file")
    parser.add_argument("--web", action="store_true", help="Start the web interface")
    parser.add_argument("--output", type=str, help="Output file for scan results")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--depth", type=int, default=2, help="Maximum crawl depth")
    parser.add_argument("--threads", type=int, default=4, help="Number of threads to use")
    parser.add_argument("--port", type=int, default=5000, help="Web server port (when using --web)")
    
    return parser.parse_args()

def main():
    """Main function to run the vulnerability scanner."""
    # Create logs directory if it doesn't exist
    os.makedirs("logs", exist_ok=True)
    
    # Parse arguments
    args = parse_arguments()
    
    # Set logging level based on verbosity
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Load configuration
    config = load_config(args.config)
    
    if args.web:
        # Start web server
        logger.info(f"Starting web interface on port {args.port}")
        start_server(host='0.0.0.0', port=args.port, debug=args.verbose)
    elif args.url:
        # Run scanner directly
        logger.info(f"Starting scan on {args.url}")
        
        # Update config with command line arguments
        scan_config = config.copy()
        scan_config.update({
            "target_url": args.url,
            "max_depth": args.depth,
            "threads": args.threads
        })
        
        # Create scanner and run scan
        scanner = Scanner(scan_config)
        results = scanner.run_scan()
        
        # Save results if output file specified
        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Scan results saved to {args.output}")
            
        # Print summary
        vuln_count = len(results.get("vulnerabilities", []))
        logger.info(f"Scan completed. Found {vuln_count} vulnerabilities.")
        
        if vuln_count > 0:
            print("\nVulnerabilities Summary:")
            for i, vuln in enumerate(results.get("vulnerabilities", [])[:10], 1):
                severity = vuln.get("severity", "Unknown").upper()
                vuln_type = vuln.get("type", "Unknown")
                url = vuln.get("url", "")
                print(f"{i}. [{severity}] {vuln_type} at {url}")
            
            if vuln_count > 10:
                print(f"... and {vuln_count - 10} more vulnerabilities.")
    else:
        logger.error("No URL provided and web interface not enabled. Use --url or --web.")
        sys.exit(1)

if __name__ == "__main__":
    main() 