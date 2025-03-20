"""
AI-powered vulnerability analysis and prioritization.
"""

import logging
import os
import json
import numpy as np
from typing import Dict, List, Any, Optional
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import tensorflow as tf

logger = logging.getLogger(__name__)

class VulnerabilityAnalyzer:
    """AI-powered vulnerability analyzer for prioritization and remediation advice."""
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the vulnerability analyzer.
        
        Args:
            model_path: Path to pre-trained model files (if None, use default models)
        """
        self.model_path = model_path or os.path.join(os.path.dirname(__file__), "models")
        self.models = self._load_models()
        logger.info("Vulnerability analyzer initialized")
    
    def _load_models(self) -> Dict[str, Any]:
        """
        Load AI models for vulnerability analysis.
        
        Returns:
            Dictionary of loaded models
        """
        models = {}
        
        try:
            # Load TF-IDF vectorizer
            vectorizer_path = os.path.join(self.model_path, "tfidf_vectorizer.pkl")
            if os.path.exists(vectorizer_path):
                import pickle
                with open(vectorizer_path, "rb") as f:
                    models["vectorizer"] = pickle.load(f)
            else:
                # Create a new vectorizer if no model exists
                models["vectorizer"] = TfidfVectorizer(max_features=1000)
                logger.warning(f"No TF-IDF vectorizer found at {vectorizer_path}, creating a new one")
                
            # Load vulnerability classifier 
            classifier_path = os.path.join(self.model_path, "vulnerability_classifier.pkl")
            if os.path.exists(classifier_path):
                import pickle
                with open(classifier_path, "rb") as f:
                    models["classifier"] = pickle.load(f)
            else:
                # Create a new classifier if no model exists
                models["classifier"] = RandomForestClassifier(n_estimators=100)
                logger.warning(f"No classifier found at {classifier_path}, creating a new one")
                
            # Load risk scorer
            risk_model_path = os.path.join(self.model_path, "risk_scorer")
            if os.path.exists(risk_model_path):
                try:
                    models["risk_scorer"] = tf.keras.models.load_model(risk_model_path)
                except Exception as e:
                    logger.error(f"Failed to load risk scorer: {str(e)}")
                    models["risk_scorer"] = None
            else:
                logger.warning(f"No risk scorer found at {risk_model_path}")
                models["risk_scorer"] = None
                
        except Exception as e:
            logger.error(f"Error loading models: {str(e)}")
        
        return models
    
    def analyze(self, vulnerabilities: List[Dict[str, Any]], pages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze vulnerabilities using AI.
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            pages: List of scanned pages
            
        Returns:
            List of vulnerabilities with AI analysis and prioritization
        """
        if not vulnerabilities:
            return []
            
        # Add contextual information
        enriched_vulnerabilities = self._enrich_vulnerabilities(vulnerabilities, pages)
        
        # Predict false positives
        filtered_vulnerabilities = self._filter_false_positives(enriched_vulnerabilities)
        
        # Calculate risk scores
        scored_vulnerabilities = self._calculate_risk_scores(filtered_vulnerabilities)
        
        # Generate remediation recommendations
        final_vulnerabilities = self._generate_recommendations(scored_vulnerabilities)
        
        return final_vulnerabilities
    
    def _enrich_vulnerabilities(
        self, vulnerabilities: List[Dict[str, Any]], pages: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Add contextual information to vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerabilities
            pages: List of scanned pages
            
        Returns:
            Enriched vulnerabilities with additional context
        """
        enriched = []
        
        # Create a page lookup dictionary for faster access
        page_lookup = {page["url"]: page for page in pages}
        
        for vuln in vulnerabilities:
            enriched_vuln = vuln.copy()
            
            # Add page context
            url = vuln.get("url", "")
            if url in page_lookup:
                page = page_lookup[url]
                enriched_vuln["page_title"] = page.get("title", "")
                enriched_vuln["page_depth"] = page.get("depth", 0)
                
            # Add timestamp for ML features
            from datetime import datetime
            enriched_vuln["timestamp"] = datetime.now().isoformat()
            
            # Add exploit probability based on vulnerability type
            exploit_probabilities = {
                "sql_injection": 0.85,
                "xss": 0.75,
                "csrf": 0.6,
                "idor": 0.8,
            }
            vuln_type = vuln.get("type", "unknown").lower()
            enriched_vuln["exploit_probability"] = exploit_probabilities.get(vuln_type, 0.5)
            
            enriched.append(enriched_vuln)
        
        return enriched
    
    def _filter_false_positives(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter out potential false positives using ML.
        
        Args:
            vulnerabilities: List of vulnerabilities
            
        Returns:
            Filtered list of vulnerabilities
        """
        # For now, use a simple heuristic approach
        # This would be replaced with actual ML model prediction
        filtered = []
        
        for vuln in vulnerabilities:
            # Simple heuristic: look at the evidence and param patterns
            evidence = vuln.get("evidence", "")
            param = vuln.get("param", "")
            
            # Filter out common false positives
            is_false_positive = False
            
            # SQL injection false positive patterns
            if vuln.get("type") == "sql_injection":
                false_positive_patterns = ["syntax error in your SQL syntax"]
                if any(pattern in evidence for pattern in false_positive_patterns):
                    # Skip this one if it matches known false positive patterns
                    is_false_positive = True
            
            # Add the vulnerability if it's not a false positive
            if not is_false_positive:
                filtered.append(vuln)
                
        return filtered
    
    def _calculate_risk_scores(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Calculate risk scores for vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerabilities
            
        Returns:
            Vulnerabilities with risk scores
        """
        scored = []
        
        # Severity weight factors
        severity_weights = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.2,
            "info": 0.1
        }
        
        # Vulnerability type weights
        vuln_type_weights = {
            "sql_injection": 0.9,
            "xss": 0.8,
            "idor": 0.85,
            "csrf": 0.75
        }
        
        for vuln in vulnerabilities:
            scored_vuln = vuln.copy()
            
            # Extract relevant factors
            severity = vuln.get("severity", "medium").lower()
            vuln_type = vuln.get("type", "unknown").lower()
            exploit_probability = vuln.get("exploit_probability", 0.5)
            
            # Calculate risk score (simplified approach)
            # A real system would use the ML model here
            severity_factor = severity_weights.get(severity, 0.5)
            type_factor = vuln_type_weights.get(vuln_type, 0.5)
            
            # Calculate CVSS-like score (0-10)
            risk_score = 10.0 * (severity_factor * 0.4 + type_factor * 0.4 + exploit_probability * 0.2)
            scored_vuln["risk_score"] = round(risk_score, 1)
            
            # Set risk level based on score
            if risk_score >= 8.0:
                scored_vuln["risk_level"] = "critical"
            elif risk_score >= 6.0:
                scored_vuln["risk_level"] = "high"
            elif risk_score >= 4.0:
                scored_vuln["risk_level"] = "medium"
            elif risk_score >= 2.0:
                scored_vuln["risk_level"] = "low"
            else:
                scored_vuln["risk_level"] = "info"
                
            scored.append(scored_vuln)
        
        # Sort by risk score (descending)
        scored.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
        
        return scored
    
    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate remediation recommendations for vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerabilities
            
        Returns:
            Vulnerabilities with remediation recommendations
        """
        recommendations = {
            "sql_injection": {
                "title": "SQL Injection Remediation",
                "description": "Protect against SQL injection by using parameterized queries or prepared statements.",
                "steps": [
                    "Use parameterized queries or prepared statements",
                    "Apply input validation and sanitization",
                    "Use ORM frameworks that automatically handle SQL escaping",
                    "Apply the principle of least privilege to database accounts",
                    "Consider using stored procedures for database access"
                ],
                "code_examples": {
                    "php": "// Use prepared statements\n$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');\n$stmt->execute([$id]);",
                    "python": "# Use parameterized queries\ncursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
                    "java": "// Use PreparedStatement\nPreparedStatement stmt = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\nstmt.setInt(1, userId);"
                }
            },
            "xss": {
                "title": "Cross-Site Scripting (XSS) Remediation",
                "description": "Protect against XSS by escaping output and using content security policy.",
                "steps": [
                    "Always encode/escape output in HTML context",
                    "Use proper context-aware escaping for JavaScript, HTML, CSS, URLs",
                    "Implement Content Security Policy (CSP)",
                    "Use modern frameworks that automatically escape output",
                    "Apply input validation and sanitization"
                ],
                "code_examples": {
                    "php": "// Escape output\necho htmlspecialchars($data, ENT_QUOTES, 'UTF-8');",
                    "javascript": "// Use textContent instead of innerHTML\nelement.textContent = userInput;",
                    "html": "<!-- Use CSP header -->\n<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self';\">"
                }
            },
            "csrf": {
                "title": "Cross-Site Request Forgery (CSRF) Remediation",
                "description": "Protect against CSRF by implementing anti-CSRF tokens.",
                "steps": [
                    "Implement CSRF tokens for all state-changing operations",
                    "Use the SameSite attribute for cookies (set to Lax or Strict)",
                    "Verify the Origin/Referer header for sensitive actions",
                    "Use proper HTTP methods (GET for read-only, POST/PUT for state changes)"
                ],
                "code_examples": {
                    "php": "<?php\n// Generate CSRF token\n$token = bin2hex(random_bytes(32));\n$_SESSION['csrf_token'] = $token;\n?>\n<form method=\"post\">\n  <input type=\"hidden\" name=\"csrf_token\" value=\"<?= $token ?>\">\n  <!-- form fields -->\n</form>",
                    "python": "# Using Django\n{% csrf_token %}",
                    "javascript": "// Add CSRF token to AJAX requests\nfetch('/api/resource', {\n  method: 'POST',\n  headers: {\n    'X-CSRF-Token': document.querySelector('meta[name=\"csrf-token\"]').content\n  },\n  // other fetch options\n});"
                }
            },
            "idor": {
                "title": "Insecure Direct Object Reference (IDOR) Remediation",
                "description": "Protect against IDOR by implementing proper access controls.",
                "steps": [
                    "Use indirect references (e.g., session-specific mapping tables instead of direct IDs)",
                    "Implement proper authorization checks for every access to a protected resource",
                    "Use UUID instead of sequential IDs where appropriate",
                    "Apply the principle of least privilege"
                ],
                "code_examples": {
                    "php": "<?php\n// Check if user has permission to access the resource\nif (!hasAccess($currentUser, $resourceId)) {\n  http_response_code(403);\n  exit('Access denied');\n}",
                    "python": "# Example access control check\ndef get_resource(resource_id):\n    resource = Resource.objects.get(id=resource_id)\n    if not resource.can_be_accessed_by(current_user):\n        raise PermissionDenied()\n    return resource",
                    "java": "// Example authorization check\npublic Resource getResource(Long resourceId) {\n    Resource resource = resourceRepository.findById(resourceId);\n    if (!authorizationService.canAccess(getCurrentUser(), resource)) {\n        throw new AccessDeniedException();\n    }\n    return resource;\n}"
                }
            }
        }
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "unknown").lower()
            if vuln_type in recommendations:
                vuln["recommendation"] = recommendations[vuln_type]
        
        return vulnerabilities