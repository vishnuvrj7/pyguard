"""
Settings Module

This module provides configuration settings for the PyGuard IDS.
"""

import os
import json
import logging

def default_settings():
    """Get default settings for the IDS.
    
    Returns:
        dict: Default settings
    """
    return {
        # Network interface to monitor
        'interface': None,  # Will be auto-detected if None
        
        # Packet filter (BPF syntax)
        'packet_filter': '',  # Empty string means no filter
        
        # Logging
        'log_level': 'INFO',
        'log_file': 'pyguard.log',
        
        # Alerts
        'alert_file': 'alerts.json',
        'alert_log_enabled': True,
        'alert_time_window': 60,  # seconds
        
        # Alert thresholds for rate limiting
        'low_alert_threshold': 10,
        'medium_alert_threshold': 5,
        'high_alert_threshold': 1,
        
        # Detection thresholds
        'port_scan_threshold': 15,  # Number of ports
        'port_scan_time_threshold': 5,  # seconds
        'dos_packet_threshold': 100,  # Number of packets
        'dos_time_threshold': 1,  # seconds
        
        # Analysis settings
        'history_size': 100,  # Number of packets to keep in history
        'time_window': 60,  # seconds
        
        # Alert actions
        'low_alert_actions': [],
        'medium_alert_actions': [],
        'high_alert_actions': [
            {
                'type': 'email',
                'recipient': 'admin@example.com',
                'subject': 'PyGuard IDS High Severity Alert'
            }
        ]
    }

def load_settings(config_file=None):
    """Load settings from a configuration file.
    
    Args:
        config_file (str, optional): Path to configuration file
    
    Returns:
        dict: Loaded settings
    """
    # Start with default settings
    settings = default_settings()
    
    # If no config file specified, look for default locations
    if config_file is None:
        potential_configs = [
            'config.json',
            os.path.expanduser('~/.pyguard/config.json'),
            '/etc/pyguard/config.json'
        ]
        for cfg in potential_configs:
            if os.path.exists(cfg):
                config_file = cfg
                break
    
    # Load settings from file if it exists
    if config_file and os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                file_settings = json.load(f)
                # Update settings with file values
                settings.update(file_settings)
            logging.info(f"Loaded settings from {config_file}")
        except Exception as e:
            logging.error(f"Error loading settings from {config_file}: {e}")
    else:
        logging.warning(f"Configuration file not found, using default settings")
    
    return settings

def save_settings(settings, config_file='config.json'):
    """Save settings to a configuration file.
    
    Args:
        settings (dict): Settings to save
        config_file (str, optional): Path to configuration file
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Create directory if it doesn't exist
        config_dir = os.path.dirname(config_file)
        if config_dir and not os.path.exists(config_dir):
            os.makedirs(config_dir)
        
        # Write settings to file
        with open(config_file, 'w') as f:
            json.dump(settings, f, indent=2)
        
        logging.info(f"Saved settings to {config_file}")
        return True
    except Exception as e:
        logging.error(f"Error saving settings to {config_file}: {e}")
        return False