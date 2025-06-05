"""
Rules Module

This module provides detection rules for the PyGuard IDS.
"""

import os
import json
import logging

def default_rules():
    """Get default detection rules.
    
    Returns:
        list: Default rules
    """
    return [
        # Port scanning detection
        {
            'id': 'PORT_SCAN_1',
            'type': 'tcp',
            'message': 'TCP SYN scan detected',
            'flags': 'S',
            'severity': 'medium'
        },
        
        # SSH brute force detection
        {
            'id': 'SSH_BRUTE_FORCE_1',
            'type': 'tcp',
            'dst_port': 22,
            'message': 'Potential SSH brute force attack',
            'severity': 'high'
        },
        
        # FTP brute force detection
        {
            'id': 'FTP_BRUTE_FORCE_1',
            'type': 'tcp',
            'dst_port': 21,
            'message': 'Potential FTP brute force attack',
            'severity': 'high'
        },
        
        # HTTP SQL injection detection
        {
            'id': 'SQL_INJECTION_1',
            'type': 'tcp',
            'dst_port': 80,
            'pattern': r'(\\b(select|union|insert|update|delete|drop|alter)\\b.*\\b(from|into|where|table|database)\\b)',
            'message': 'Potential SQL injection attack',
            'severity': 'high'
        },
        
        # HTTP XSS detection
        {
            'id': 'XSS_1',
            'type': 'tcp',
            'dst_port': 80,
            'pattern': r'(<script>|<img[^>]+\\bon\\w+\\s*=|javascript:)',
            'message': 'Potential XSS attack',
            'severity': 'high'
        },
        
        # ICMP flood detection
        {
            'id': 'ICMP_FLOOD_1',
            'type': 'icmp',
            'icmp_type': 8,  # Echo request
            'message': 'ICMP flood detected',
            'severity': 'medium'
        },
        
        # DNS amplification detection
        {
            'id': 'DNS_AMPLIFICATION_1',
            'type': 'udp',
            'dst_port': 53,
            'message': 'Potential DNS amplification attack',
            'severity': 'high'
        },
        
        # NTP amplification detection
        {
            'id': 'NTP_AMPLIFICATION_1',
            'type': 'udp',
            'dst_port': 123,
            'message': 'Potential NTP amplification attack',
            'severity': 'high'
        },
        
        # SMB detection
        {
            'id': 'SMB_EXPLOIT_1',
            'type': 'tcp',
            'dst_port': 445,
            'message': 'Potential SMB exploit attempt',
            'severity': 'high'
        },
        
        # Telnet brute force detection
        {
            'id': 'TELNET_BRUTE_FORCE_1',
            'type': 'tcp',
            'dst_port': 23,
            'message': 'Potential Telnet brute force attack',
            'severity': 'high'
        }
    ]

def load_rules(rules_file=None):
    """Load detection rules from a file.
    
    Args:
        rules_file (str, optional): Path to rules file
    
    Returns:
        list: Loaded rules
    """
    # Start with default rules
    rules = default_rules()
    
    # If no rules file specified, look for default locations
    if rules_file is None:
        potential_rules = [
            'rules.json',
            os.path.expanduser('~/.pyguard/rules.json'),
            '/etc/pyguard/rules.json'
        ]
        for r in potential_rules:
            if os.path.exists(r):
                rules_file = r
                break
    
    # Load rules from file if it exists
    if rules_file and os.path.exists(rules_file):
        try:
            with open(rules_file, 'r') as f:
                file_rules = json.load(f)
                # Replace default rules with file rules
                rules = file_rules
            logging.info(f"Loaded {len(rules)} rules from {rules_file}")
        except Exception as e:
            logging.error(f"Error loading rules from {rules_file}: {e}")
    else:
        logging.warning(f"Rules file not found, using default rules")
    
    return rules

def save_rules(rules, rules_file='rules.json'):
    """Save rules to a file.
    
    Args:
        rules (list): Rules to save
        rules_file (str, optional): Path to rules file
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Create directory if it doesn't exist
        rules_dir = os.path.dirname(rules_file)
        if rules_dir and not os.path.exists(rules_dir):
            os.makedirs(rules_dir)
        
        # Write rules to file
        with open(rules_file, 'w') as f:
            json.dump(rules, f, indent=2)
        
        logging.info(f"Saved {len(rules)} rules to {rules_file}")
        return True
    except Exception as e:
        logging.error(f"Error saving rules to {rules_file}: {e}")
        return False