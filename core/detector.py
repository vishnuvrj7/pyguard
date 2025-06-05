"""
Rule-Based Detector Module

This module implements a rule-based detection engine for identifying
potential intrusions and suspicious activities in network traffic.
"""

import logging
import re
from config.rules import load_rules

class RuleBasedDetector:
    """Class for detecting intrusions based on rules."""
    
    def __init__(self, settings, alert_manager):
        """Initialize the rule-based detector.
        
        Args:
            settings (dict): Configuration settings
            alert_manager (AlertManager): The alert manager for generating alerts
        """
        self.settings = settings
        self.alert_manager = alert_manager
        self.logger = logging.getLogger('pyguard.detector')
        
        # Load detection rules
        self.rules = load_rules()
        self.logger.info(f"Loaded {len(self.rules)} detection rules")
        
        # Compile regex patterns for payload inspection
        self.compile_patterns()
    
    def compile_patterns(self):
        """Compile regex patterns from rules for efficient matching."""
        for rule in self.rules:
            if 'pattern' in rule and isinstance(rule['pattern'], str):
                try:
                    rule['compiled_pattern'] = re.compile(rule['pattern'], re.IGNORECASE)
                except re.error as e:
                    self.logger.error(f"Error compiling pattern for rule {rule['id']}: {e}")
                    rule['compiled_pattern'] = None
    
    def check_packet(self, packet):
        """Check a packet against general rules.
        
        Args:
            packet: The packet to check
        """
        for rule in self.rules:
            if rule.get('type') == 'general':
                if self.match_rule(rule, packet):
                    self.trigger_alert(rule, packet)
    
    def check_tcp_packet(self, packet, src_ip, dst_ip, src_port, dst_port, flags):
        """Check a TCP packet against TCP-specific rules.
        
        Args:
            packet: The packet to check
            src_ip (str): Source IP address
            dst_ip (str): Destination IP address
            src_port (int): Source port
            dst_port (int): Destination port
            flags: TCP flags
        """
        for rule in self.rules:
            if rule.get('type') == 'tcp':
                # Check port rules
                if 'dst_port' in rule and rule['dst_port'] != dst_port:
                    continue
                
                # Check flag rules
                if 'flags' in rule and not self.check_tcp_flags(flags, rule['flags']):
                    continue
                
                # Check payload pattern
                if self.match_rule(rule, packet):
                    self.trigger_alert(rule, packet, src_ip, dst_ip, src_port, dst_port)
    
    def check_udp_packet(self, packet, src_ip, dst_ip, src_port, dst_port):
        """Check a UDP packet against UDP-specific rules.
        
        Args:
            packet: The packet to check
            src_ip (str): Source IP address
            dst_ip (str): Destination IP address
            src_port (int): Source port
            dst_port (int): Destination port
        """
        for rule in self.rules:
            if rule.get('type') == 'udp':
                # Check port rules
                if 'dst_port' in rule and rule['dst_port'] != dst_port:
                    continue
                
                # Check payload pattern
                if self.match_rule(rule, packet):
                    self.trigger_alert(rule, packet, src_ip, dst_ip, src_port, dst_port)
    
    def check_icmp_packet(self, packet, src_ip, dst_ip, icmp_type, icmp_code):
        """Check an ICMP packet against ICMP-specific rules.
        
        Args:
            packet: The packet to check
            src_ip (str): Source IP address
            dst_ip (str): Destination IP address
            icmp_type (int): ICMP type
            icmp_code (int): ICMP code
        """
        for rule in self.rules:
            if rule.get('type') == 'icmp':
                # Check ICMP type/code rules
                if 'icmp_type' in rule and rule['icmp_type'] != icmp_type:
                    continue
                if 'icmp_code' in rule and rule['icmp_code'] != icmp_code:
                    continue
                
                # Check payload pattern
                if self.match_rule(rule, packet):
                    self.trigger_alert(rule, packet, src_ip, dst_ip)
    
    def match_rule(self, rule, packet):
        """Match a packet against a rule's pattern.
        
        Args:
            rule (dict): The rule to match against
            packet: The packet to check
        
        Returns:
            bool: True if the packet matches the rule, False otherwise
        """
        # Skip if no pattern to match
        if 'compiled_pattern' not in rule or rule['compiled_pattern'] is None:
            return False
        
        # Extract payload if available
        payload = None
        if hasattr(packet, 'load'):
            payload = packet.load
        elif 'Raw' in packet:
            payload = packet['Raw'].load
        
        # No payload to match against
        if payload is None:
            return False
        
        # Try to decode payload if it's bytes
        if isinstance(payload, bytes):
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
            except:
                payload_str = str(payload)
        else:
            payload_str = str(payload)
        
        # Match pattern against payload
        return bool(rule['compiled_pattern'].search(payload_str))
    
    def check_tcp_flags(self, packet_flags, rule_flags):
        """Check if packet flags match rule flags.
        
        Args:
            packet_flags: The flags from the packet
            rule_flags (str): The flags specified in the rule
        
        Returns:
            bool: True if flags match, False otherwise
        """
        # Convert packet flags to string representation
        packet_flags_str = str(packet_flags)
        
        # Simple string matching for now
        # This could be enhanced with more sophisticated flag matching
        return rule_flags in packet_flags_str
    
    def report_port_scan(self, src_ip, dst_ip, ports):
        """Report a detected port scan.
        
        Args:
            src_ip (str): Source IP address
            dst_ip (str): Destination IP address
            ports (set): Set of scanned ports
        """
        alert_data = {
            'type': 'port_scan',
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'ports': sorted(list(ports)),
            'severity': 'medium',
            'message': f"Potential port scan from {src_ip} to {dst_ip}, {len(ports)} ports"
        }
        self.alert_manager.generate_alert(alert_data)
    
    def report_dos_attack(self, src_ip, dst_ip, packet_count):
        """Report a detected DoS attack.
        
        Args:
            src_ip (str): Source IP address
            dst_ip (str): Destination IP address
            packet_count (int): Number of packets detected
        """
        alert_data = {
            'type': 'dos_attack',
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'packet_count': packet_count,
            'severity': 'high',
            'message': f"Potential DoS attack from {src_ip} to {dst_ip}, {packet_count} packets"
        }
        self.alert_manager.generate_alert(alert_data)
    
    def trigger_alert(self, rule, packet, src_ip=None, dst_ip=None, src_port=None, dst_port=None):
        """Trigger an alert based on a rule match.
        
        Args:
            rule (dict): The matched rule
            packet: The packet that triggered the alert
            src_ip (str, optional): Source IP address
            dst_ip (str, optional): Destination IP address
            src_port (int, optional): Source port
            dst_port (int, optional): Destination port
        """
        # Extract IP addresses from packet if not provided
        if src_ip is None and 'IP' in packet:
            src_ip = packet['IP'].src
        if dst_ip is None and 'IP' in packet:
            dst_ip = packet['IP'].dst
        
        # Extract ports from packet if not provided
        if src_port is None and 'TCP' in packet:
            src_port = packet['TCP'].sport
        elif src_port is None and 'UDP' in packet:
            src_port = packet['UDP'].sport
            
        if dst_port is None and 'TCP' in packet:
            dst_port = packet['TCP'].dport
        elif dst_port is None and 'UDP' in packet:
            dst_port = packet['UDP'].dport
        
        # Create alert data
        alert_data = {
            'rule_id': rule.get('id', 'unknown'),
            'type': rule.get('type', 'unknown'),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'severity': rule.get('severity', 'low'),
            'message': rule.get('message', 'Unknown alert')
        }
        
        # Generate the alert
        self.alert_manager.generate_alert(alert_data)