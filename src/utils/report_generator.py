"""
Report generator for vulnerability scan results.
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

def generate_report(scan_results: Dict[str, Any], output_file: str) -> None:
    """
    Generate a report from scan results.
    
    Args:
        scan_results: Scan results dictionary
        output_file: Path to output file
    """
    file_ext = output_file.split(".")[-1].lower()
    
    if file_ext == "json":
        _generate_json_report(scan_results, output_file)
    elif file_ext == "html":
        _generate_html_report(scan_results, output_file)
    elif file_ext == "pdf":
        _generate_pdf_report(scan_results, output_file)
    else:
        logger.warning(f"Unsupported report format: {file_ext}, defaulting to HTML")
        _generate_html_report(scan_results, f"{output_file}.html")
        
def _generate_json_report(scan_results: Dict[str, Any], output_file: str) -> None:
    """
    Generate a JSON report.
    
    Args:
        scan_results: Scan results dictionary
        output_file: Path to output file
    """
    try:
        with open(output_file, "w") as f:
            json.dump(scan_results, f, indent=2)
        logger.info(f"JSON report saved to {output_file}")
    except Exception as e:
        logger.error(f"Error generating JSON report: {str(e)}")
        
def _generate_html_report(scan_results: Dict[str, Any], output_file: str) -> None:
    """
    Generate an HTML report.
    
    Args:
        scan_results: Scan results dictionary
        output_file: Path to output file
    """
    try:
        # Extract data from scan results
        target_url = scan_results.get("target_url", "Unknown")
        scan_time = scan_results.get("scan_time", datetime.now().timestamp())
        scan_date = datetime.fromtimestamp(scan_time).strftime("%Y-%m-%d %H:%M:%S")
        scan_duration = scan_results.get("scan_duration", 0)
        pages_scanned = scan_results.get("pages_scanned", 0)
        vulnerabilities = scan_results.get("vulnerabilities", [])
        summary = scan_results.get("summary", {})
        
        # Count vulnerabilities by severity
        severity_counts = summary.get("severity_counts", {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        })
        
        # Generate HTML content
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report - {target_url}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        h1, h2, h3 {{
            margin-top: 0;
        }}
        .summary-box {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 30px;
            flex-wrap: wrap;
        }}
        .summary-item {{
            flex: 1;
            min-width: 200px;
            background-color: #f9f9f9;
            border-radius: 5px;
            padding: 15px;
            margin: 10px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .severity-distribution {{
            display: flex;
            margin-bottom: 20px;
        }}
        .severity-bar {{
            height: 30px;
            border-radius: 3px;
            margin-right: 2px;
            text-align: center;
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .severity-critical {{ background-color: #e74c3c; }}
        .severity-high {{ background-color: #e67e22; }}
        .severity-medium {{ background-color: #f39c12; }}
        .severity-low {{ background-color: #3498db; }}
        .severity-info {{ background-color: #2ecc71; }}
        
        .vulnerability-table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
        }}
        .vulnerability-table th, .vulnerability-table td {{
            padding: 12px 15px;
            border-bottom: 1px solid #ddd;
            text-align: left;
        }}
        .vulnerability-table th {{
            background-color: #f2f2f2;
            font-weight: bold;
        }}
        .vulnerability-table tr:hover {{
            background-color: #f5f5f5;
        }}
        .pill {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            color: white;
        }}
        .recommendation {{
            background-color: #f9f9f9;
            border-radius: 5px;
            padding: 15px;
            margin: 20px 0;
        }}
        .code-block {{
            background-color: #f4f4f4;
            padding: 15px;
            border-radius: 5px;
            font-family: monospace;
            white-space: pre-wrap;
            overflow-x: auto;
        }}
        .footer {{
            margin-top: 50px;
            text-align: center;
            color: #7f8c8d;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>AI-Enhanced Vulnerability Scan Report</h1>
            <p>Target: {target_url}</p>
        </header>
        
        <section>
            <h2>Scan Summary</h2>
            <div class="summary-box">
                <div class="summary-item">
                    <h3>Scan Information</h3>
                    <p><strong>Date:</strong> {scan_date}</p>
                    <p><strong>Duration:</strong> {scan_duration:.2f} seconds</p>
                    <p><strong>Pages Scanned:</strong> {pages_scanned}</p>
                </div>
                
                <div class="summary-item">
                    <h3>Vulnerability Summary</h3>
                    <p><strong>Total Vulnerabilities:</strong> {summary.get("total_vulnerabilities", 0)}</p>
                    <div class="severity-distribution">
                        <div class="severity-bar severity-critical" style="width: {max(1, severity_counts.get('critical', 0) * 30)}px">
                            {severity_counts.get('critical', 0)}
                        </div>
                        <div class="severity-bar severity-high" style="width: {max(1, severity_counts.get('high', 0) * 30)}px">
                            {severity_counts.get('high', 0)}
                        </div>
                        <div class="severity-bar severity-medium" style="width: {max(1, severity_counts.get('medium', 0) * 30)}px">
                            {severity_counts.get('medium', 0)}
                        </div>
                        <div class="severity-bar severity-low" style="width: {max(1, severity_counts.get('low', 0) * 30)}px">
                            {severity_counts.get('low', 0)}
                        </div>
                        <div class="severity-bar severity-info" style="width: {max(1, severity_counts.get('info', 0) * 30)}px">
                            {severity_counts.get('info', 0)}
                        </div>
                    </div>
                    <p><small>Critical / High / Medium / Low / Info</small></p>
                </div>
            </div>
        </section>
        
        <section>
            <h2>Detected Vulnerabilities</h2>
"""
        
        # Generate vulnerability entries
        if vulnerabilities:
            html_content += """
            <table class="vulnerability-table">
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>URL</th>
                        <th>Parameter</th>
                        <th>Severity</th>
                        <th>Risk Score</th>
                    </tr>
                </thead>
                <tbody>
"""
            
            for vuln in vulnerabilities:
                vuln_type = vuln.get("type", "unknown").upper()
                url = vuln.get("url", "")
                param = vuln.get("param", "N/A")
                severity = vuln.get("severity", "medium").lower()
                risk_score = vuln.get("risk_score", "N/A")
                
                # Map severity to CSS class
                severity_class = f"severity-{severity}"
                
                html_content += f"""
                    <tr>
                        <td>{vuln_type}</td>
                        <td>{url}</td>
                        <td>{param}</td>
                        <td><span class="pill {severity_class}">{severity.upper()}</span></td>
                        <td>{risk_score}</td>
                    </tr>
"""
            
            html_content += """
                </tbody>
            </table>
"""
            
            # Add vulnerability details
            html_content += """
            <h2>Vulnerability Details</h2>
"""
            
            for i, vuln in enumerate(vulnerabilities):
                vuln_type = vuln.get("type", "unknown").upper()
                url = vuln.get("url", "")
                method = vuln.get("method", "GET")
                param = vuln.get("param", "N/A")
                evidence = vuln.get("evidence", "")
                severity = vuln.get("severity", "medium").lower()
                risk_score = vuln.get("risk_score", "N/A")
                risk_level = vuln.get("risk_level", severity).lower()
                
                recommendation = vuln.get("recommendation", {})
                recommendation_title = recommendation.get("title", "")
                recommendation_description = recommendation.get("description", "")
                recommendation_steps = recommendation.get("steps", [])
                code_examples = recommendation.get("code_examples", {})
                
                html_content += f"""
            <div class="vulnerability-detail">
                <h3>{i+1}. {vuln_type} - <span class="pill severity-{risk_level}">{risk_level.upper()}</span></h3>
                <p><strong>URL:</strong> {url}</p>
                <p><strong>Method:</strong> {method}</p>
                <p><strong>Parameter:</strong> {param}</p>
                <p><strong>Risk Score:</strong> {risk_score}</p>
                
                {f'<p><strong>Evidence:</strong> {evidence}</p>' if evidence else ''}
                
                {f'''
                <div class="recommendation">
                    <h4>{recommendation_title}</h4>
                    <p>{recommendation_description}</p>
                    
                    <h5>Remediation Steps:</h5>
                    <ol>
                        {"".join(f'<li>{step}</li>' for step in recommendation_steps)}
                    </ol>
                    
                    {f'''
                    <h5>Code Examples:</h5>
                    {"".join(f'<p><strong>{lang.capitalize()}:</strong></p><div class="code-block">{code}</div>' for lang, code in code_examples.items())}
                    ''' if code_examples else ''}
                </div>
                ''' if recommendation else ''}
            </div>
"""
            
        else:
            html_content += """
            <p>No vulnerabilities detected.</p>
"""
        
        # Finish HTML document
        html_content += """
        </section>
        
        <div class="footer">
            <p>Generated by AI-Enhanced Web Vulnerability Scanner</p>
        </div>
    </div>
</body>
</html>
"""
        
        # Write HTML content to file
        with open(output_file, "w") as f:
            f.write(html_content)
            
        logger.info(f"HTML report saved to {output_file}")
        
    except Exception as e:
        logger.error(f"Error generating HTML report: {str(e)}")

def _generate_pdf_report(scan_results: Dict[str, Any], output_file: str) -> None:
    """
    Generate a PDF report.
    
    Args:
        scan_results: Scan results dictionary
        output_file: Path to output file
    """
    try:
        # Generate HTML report first
        html_file = f"{output_file}.html"
        _generate_html_report(scan_results, html_file)
        
        # Try to use weasyprint to convert HTML to PDF
        try:
            import weasyprint
            html = weasyprint.HTML(filename=html_file)
            html.write_pdf(output_file)
            logger.info(f"PDF report saved to {output_file}")
            
            # Clean up temporary HTML file
            os.remove(html_file)
            
        except ImportError:
            logger.warning("WeasyPrint not installed, keeping HTML report")
            logger.info(f"HTML report saved to {html_file}")
            
    except Exception as e:
        logger.error(f"Error generating PDF report: {str(e)}")