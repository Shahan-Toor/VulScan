"""
Web interface for the vulnerability scanner.
"""

import os
import json
import logging
import threading
from typing import Dict, List, Any, Optional
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, abort, send_from_directory

from src.core.scanner import Scanner
from src.database.db_manager import DatabaseManager
from src.utils.config import load_config

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, 
            template_folder=os.path.join(os.path.dirname(__file__), "templates"),
            static_folder=os.path.join(os.path.dirname(__file__), "static"))

# Initialize database manager
db_manager = DatabaseManager()

# Dict to store currently running scans
active_scans: Dict[str, Dict[str, Any]] = {}

# Add Jinja2 filters
@app.template_filter('timestampformat')
def format_timestamp(timestamp):
    """Format a timestamp to a readable date/time."""
    try:
        dt = datetime.fromtimestamp(float(timestamp))
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return "Invalid date"

@app.route('/')
def home():
    """Render the main dashboard page."""
    # Get basic statistics
    stats = db_manager.get_scan_statistics()
    
    # Get recent scans
    recent_scans = db_manager.get_scan_history(limit=5)
    
    return render_template('dashboard.html', stats=stats, recent_scans=recent_scans)

@app.route('/scans')
def scans():
    """Render the scans history page."""
    # Get pagination parameters
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 10))
    offset = (page - 1) * limit
    
    # Get scan history
    scan_history = db_manager.get_scan_history(limit=limit, offset=offset)
    
    return render_template('scans.html', scans=scan_history, page=page, limit=limit)

@app.route('/scan/<int:scan_id>')
def scan_details(scan_id):
    """Render the scan details page."""
    # Get scan details
    scan = db_manager.get_scan_details(scan_id)
    
    if not scan:
        abort(404)
    
    return render_template('scan_details.html', scan=scan)

@app.route('/vulnerabilities')
def vulnerabilities():
    """Render the vulnerabilities search page."""
    # Get filter parameters
    vuln_type = request.args.get('type')
    severity = request.args.get('severity')
    url_pattern = request.args.get('url')
    
    # Search vulnerabilities
    vulns = db_manager.search_vulnerabilities(
        vuln_type=vuln_type, 
        severity=severity, 
        url_pattern=url_pattern
    )
    
    return render_template('vulnerabilities.html', 
                          vulnerabilities=vulns, 
                          type_filter=vuln_type,
                          severity_filter=severity,
                          url_filter=url_pattern)

@app.route('/new_scan', methods=['GET', 'POST'])
def new_scan():
    """Handle new scan submission."""
    if request.method == 'POST':
        # Get scan parameters
        target_url = request.form.get('target_url')
        scan_depth = int(request.form.get('scan_depth', 2))
        scan_threads = int(request.form.get('scan_threads', 4))
        scan_timeout = int(request.form.get('scan_timeout', 30))
        
        # Check params
        if not target_url:
            return render_template('new_scan.html', error="Target URL is required"), 400
        
        # Generate scan ID
        import uuid
        scan_id = str(uuid.uuid4())
        
        # Start scan in background thread
        threading.Thread(
            target=_run_scan_thread,
            args=(scan_id, target_url, scan_depth, scan_threads, scan_timeout),
            daemon=True
        ).start()
        
        # Redirect to scan status page
        return redirect(url_for('scan_status', scan_id=scan_id))
    
    # GET request - render the new scan form
    return render_template('new_scan.html')

@app.route('/scan_status/<scan_id>')
def scan_status(scan_id):
    """Render the scan status page."""
    if scan_id in active_scans:
        return render_template('scan_status.html', 
                              scan_id=scan_id, 
                              status=active_scans[scan_id])
    
    # Check if scan has completed and is in database
    db_scans = db_manager.get_scan_history(limit=50)
    for scan in db_scans:
        if str(scan.get('id')) == scan_id:
            return redirect(url_for('scan_details', scan_id=scan_id))
    
    # Scan not found
    abort(404)

@app.route('/api/scan_status/<scan_id>')
def api_scan_status(scan_id):
    """API endpoint to get the current status of a scan."""
    if scan_id in active_scans:
        return jsonify(active_scans[scan_id])
    
    # Check if scan has completed and is in database
    db_scans = db_manager.get_scan_history(limit=50)
    for scan in db_scans:
        if str(scan.get('id')) == scan_id:
            return jsonify({
                "status": "completed",
                "redirect_url": url_for('scan_details', scan_id=scan_id)
            })
    
    # Scan not found
    return jsonify({"status": "not_found"}), 404

@app.route('/api/delete_scan/<int:scan_id>', methods=['DELETE'])
def api_delete_scan(scan_id):
    """API endpoint to delete a scan."""
    success = db_manager.delete_scan(scan_id)
    
    if success:
        return jsonify({"status": "success"})
    else:
        return jsonify({"status": "error", "message": "Failed to delete scan"}), 400

@app.route('/api/export_report/<int:scan_id>')
def api_export_report(scan_id):
    """API endpoint to export a scan report."""
    report_format = request.args.get('format', 'json')
    
    # Get scan details
    scan = db_manager.get_scan_details(scan_id)
    
    if not scan:
        return jsonify({"status": "error", "message": "Scan not found"}), 404
    
    # Generate report
    if report_format == 'json':
        # Return JSON directly
        return jsonify(scan)
    elif report_format == 'html':
        # Generate a standalone HTML report
        return render_template('report.html', scan=scan)
    else:
        return jsonify({"status": "error", "message": "Unsupported format"}), 400

def _run_scan_thread(scan_id: str, target_url: str, depth: int, threads: int, timeout: int) -> None:
    """
    Run a scan in a background thread.
    
    Args:
        scan_id: Unique ID for this scan
        target_url: Target URL to scan
        depth: Maximum crawl depth
        threads: Number of threads to use
        timeout: Request timeout in seconds
    """
    try:
        # Update status
        active_scans[scan_id] = {
            "status": "initializing",
            "target_url": target_url,
            "start_time": datetime.now().timestamp(),
            "progress": 0
        }
        
        # Configure scanner
        config = {
            "target_url": target_url,
            "max_depth": depth,
            "threads": threads,
            "timeout": timeout,
            "user_agent": "VulnerabilityScannerBot/1.0",
            "enable_ai_analysis": True
        }
        
        # Create scanner
        scanner = Scanner(config)
        
        # Register progress callback
        def update_progress(progress: float, message: str) -> None:
            active_scans[scan_id]["progress"] = progress
            active_scans[scan_id]["status_message"] = message
            logger.info(f"Scan {scan_id} progress: {progress:.2f}% - {message}")
        
        scanner.register_progress_callback(update_progress)
        
        # Update status
        active_scans[scan_id]["status"] = "scanning"
        
        # Run scan
        scan_results = scanner.run_scan()
        
        # Update status
        active_scans[scan_id]["status"] = "processing_results"
        active_scans[scan_id]["progress"] = 95
        
        # Save results to database
        db_scan_id = db_manager.save_scan_results(scan_results)
        
        # Update status
        active_scans[scan_id]["status"] = "completed"
        active_scans[scan_id]["progress"] = 100
        active_scans[scan_id]["db_scan_id"] = db_scan_id
        active_scans[scan_id]["end_time"] = datetime.now().timestamp()
        
        # Calculate duration
        duration = active_scans[scan_id]["end_time"] - active_scans[scan_id]["start_time"]
        active_scans[scan_id]["duration"] = duration
        
        logger.info(f"Scan {scan_id} completed in {duration:.2f} seconds")
        
        # Keep the status around for a while, then clean up
        import time
        time.sleep(300)  # Keep for 5 minutes
        if scan_id in active_scans:
            del active_scans[scan_id]
            
    except Exception as e:
        logger.error(f"Error in scan {scan_id}: {str(e)}")
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["error"] = str(e)

def start_server(host: str = '0.0.0.0', port: int = 5000, debug: bool = False) -> None:
    """
    Start the web server.
    
    Args:
        host: Host to listen on
        port: Port to listen on
        debug: Whether to run in debug mode
    """
    logger.info(f"Starting web server on {host}:{port}")
    app.run(host=host, port=port, debug=debug)

if __name__ == "__main__":
    start_server(debug=True) 