"""
Traffic Analyzer Module

This module analyzes network traffic to identify patterns and extract features
that can be used for intrusion detection.
"""

import logging
from collections import defaultdict, deque
from scapy.all import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTP
import time

class TrafficAnalyzer:
    """Class for analyzing network traffic."""
    
    def __init__(self, settings, detector):
        """Initialize the traffic analyzer.
        
        Args:
            settings (dict): Configuration settings
            detector (RuleBasedDetector): The detector to check for suspicious activities
        """
        self.settings = settings
        self.detector = detector
        self.logger = logging.getLogger('pyguard.analyzer')
        
        # Traffic statistics
        self.stats = {
            'total_packets': 0,
            'ip_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'http_packets': 0,
            'other_packets': 0,
        }
        
        # Connection tracking
        self.connections = defaultdict(lambda: {'count': 0, 'last_seen': 0, 'ports': set()})
        
        # Recent packet history for context
        self.packet_history = deque(maxlen=settings.get('history_size', 100))
        
        # Time window for rate-based analysis
        self.time_window = settings.get('time_window', 60)  # seconds
    
    def analyze_packet(self, packet):
        """Analyze a network packet.
        
        Args:
            packet: The packet to analyze
        """
        # Update statistics
        self.stats['total_packets'] += 1
        
        # Add to history
        self.packet_history.append(packet)
        
        # Extract features based on packet type
        if IP in packet:
            self.stats['ip_packets'] += 1
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Update connection tracking
            conn_key = (src_ip, dst_ip)
            self.connections[conn_key]['count'] += 1
            self.connections[conn_key]['last_seen'] = time.time()
            
            # Process TCP packets
            if TCP in packet:
                self.stats['tcp_packets'] += 1
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                self.connections[conn_key]['ports'].add(dst_port)
                
                # Check for HTTP
                if dst_port == 80 or src_port == 80 or HTTP in packet:
                    self.stats['http_packets'] += 1
                
                # Extract TCP flags for analysis
                flags = packet[TCP].flags
                
                # Pass to detector for TCP-specific rules
                self.detector.check_tcp_packet(packet, src_ip, dst_ip, src_port, dst_port, flags)
            
            # Process UDP packets
            elif UDP in packet:
                self.stats['udp_packets'] += 1
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                self.connections[conn_key]['ports'].add(dst_port)
                
                # Pass to detector for UDP-specific rules
                self.detector.check_udp_packet(packet, src_ip, dst_ip, src_port, dst_port)
            
            # Process ICMP packets
            elif ICMP in packet:
                self.stats['icmp_packets'] += 1
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code
                
                # Pass to detector for ICMP-specific rules
                self.detector.check_icmp_packet(packet, src_ip, dst_ip, icmp_type, icmp_code)
            
            else:
                self.stats['other_packets'] += 1
            
            # Check for port scanning
            self.check_port_scanning(src_ip, dst_ip)
            
            # Check for DoS attacks
            self.check_dos_attack(src_ip, dst_ip)
        
        # Pass the packet to the detector for general rules
        self.detector.check_packet(packet)
    
    def check_port_scanning(self, src_ip, dst_ip):
        """Check for port scanning behavior.
        
        Args:
            src_ip (str): Source IP address
            dst_ip (str): Destination IP address
        """
        conn_key = (src_ip, dst_ip)
        conn_data = self.connections[conn_key]
        
        # Check if many ports are being accessed in a short time
        port_threshold = self.settings.get('port_scan_threshold', 15)
        time_threshold = self.settings.get('port_scan_time_threshold', 5)  # seconds
        
        if len(conn_data['ports']) > port_threshold:
            current_time = time.time()
            if current_time - conn_data['last_seen'] < time_threshold:
                # Potential port scan detected
                self.detector.report_port_scan(src_ip, dst_ip, conn_data['ports'])
                # Reset the ports set after reporting
                conn_data['ports'] = set()
    
    def check_dos_attack(self, src_ip, dst_ip):
        """Check for potential DoS attacks.
        
        Args:
            src_ip (str): Source IP address
            dst_ip (str): Destination IP address
        """
        conn_key = (src_ip, dst_ip)
        conn_data = self.connections[conn_key]
        
        # Check for high packet rate from a single source
        packet_threshold = self.settings.get('dos_packet_threshold', 100)
        time_threshold = self.settings.get('dos_time_threshold', 1)  # seconds
        
        if conn_data['count'] > packet_threshold:
            current_time = time.time()
            if current_time - conn_data['last_seen'] < time_threshold:
                # Potential DoS attack detected
                self.detector.report_dos_attack(src_ip, dst_ip, conn_data['count'])
                # Reset the counter after reporting
                conn_data['count'] = 0
    
    def get_stats(self):
        """Get current traffic statistics.
        
        Returns:
            dict: Traffic statistics
        """
        return self.stats
    
    def get_active_connections(self):
        """Get active connections.
        
        Returns:
            dict: Active connections
        """
        # Filter out old connections
        current_time = time.time()
        active_connections = {}
        for conn_key, conn_data in self.connections.items():
            if current_time - conn_data['last_seen'] < self.time_window:
                active_connections[conn_key] = conn_data
        
        return active_connections