"""
Configuration utilities for loading and managing scanner settings.
"""

import os
import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    "zap_path": None,
    "zap_port": 8080,
    "zap_api_key": None,
    "zap_api_url": "http://localhost:8080",
    "max_depth": 3,
    "threads": 4,
    "timeout": 30,
    "user_agent": "VulnerabilityScannerBot/1.0",
    "enable_ai_analysis": True,
    "report_path": "reports",
    "excluded_paths": [
        "logout",
        ".jpg",
        ".png",
        ".gif",
        ".css",
        ".js"
    ],
    "scan_policy": "Default Policy",
    "auth": {
        "enabled": False,
        "login_url": "",
        "username": "",
        "password": "",
        "login_regex": ""
    },
    "context": {
        "name": "default",
        "include_urls": [],
        "exclude_urls": []
    },
    "spider_options": {
        "max_children": 0,
        "subtree_only": False,
        "scope_constraint": False,
        "thread_count": 5,
        "max_depth": 5,
        "max_duration": 0
    },
    "scan_options": {
        "passive_scan_only": False,
        "recursive": True
    },
    "ai": {
        "use_ml_prioritization": True,
        "use_ml_false_positive_detection": True,
        "model_update_frequency": "weekly"
    }
}

def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration from file or use defaults.
    
    Args:
        config_path: Path to configuration file (JSON)
        
    Returns:
        Configuration dictionary
    """
    config = DEFAULT_CONFIG.copy()
    
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                user_config = json.load(f)
                
            # Deep merge user config with defaults
            merge_configs(config, user_config)
            logger.info(f"Loaded configuration from {config_path}")
        except Exception as e:
            logger.error(f"Error loading configuration from {config_path}: {str(e)}")
            logger.info("Using default configuration")
    else:
        logger.info("No configuration file found, using defaults")
        
        # If no config file exists, create one with defaults
        if config_path:
            try:
                # Ensure directory exists
                os.makedirs(os.path.dirname(os.path.abspath(config_path)), exist_ok=True)
                
                with open(config_path, "w") as f:
                    json.dump(config, f, indent=2)
                logger.info(f"Created default configuration at {config_path}")
            except Exception as e:
                logger.error(f"Error creating default configuration file: {str(e)}")
    
    return config

def merge_configs(base_config: Dict[str, Any], override_config: Dict[str, Any]) -> None:
    """
    Recursively merge override_config into base_config.
    
    Args:
        base_config: Base configuration dictionary (modified in-place)
        override_config: Override configuration dictionary
    """
    for key, value in override_config.items():
        if key in base_config and isinstance(base_config[key], dict) and isinstance(value, dict):
            # Recursively merge dictionaries
            merge_configs(base_config[key], value)
        else:
            # Override or add value
            base_config[key] = value

def save_config(config: Dict[str, Any], config_path: str) -> None:
    """
    Save configuration to file.
    
    Args:
        config: Configuration dictionary
        config_path: Path to save configuration file
    """
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(os.path.abspath(config_path)), exist_ok=True)
        
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)
        logger.info(f"Configuration saved to {config_path}")
    except Exception as e:
        logger.error(f"Error saving configuration to {config_path}: {str(e)}")

def get_check_config(config: Dict[str, Any], check_name: str) -> Dict[str, Any]:
    """
    Get configuration for a specific vulnerability check.
    
    Args:
        config: Main configuration dictionary
        check_name: Name of the check
        
    Returns:
        Check-specific configuration
    """
    # Get enabled status from checks section
    is_enabled = config.get("checks", {}).get(check_name, True)
    
    # Get check-specific configuration if it exists
    check_config = config.get(check_name, {}).copy()
    
    # Add enabled status
    check_config["enabled"] = is_enabled
    
    return check_config 