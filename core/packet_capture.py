"""
Packet Capture Module

This module is responsible for capturing network packets using Scapy or Pcapy.
It provides a clean interface for starting and stopping packet capture.
"""

import threading
import time
import logging
from scapy.all import sniff, conf

class PacketCapture:
    """Class for capturing network packets."""
    
    def __init__(self, settings, analyzer):
        """Initialize the packet capture module.
        
        Args:
            settings (dict): Configuration settings
            analyzer (TrafficAnalyzer): The analyzer to process captured packets
        """
        self.settings = settings
        self.analyzer = analyzer
        self.interface = settings.get('interface', conf.iface)
        self.packet_filter = settings.get('packet_filter', '')
        self.running = False
        self.capture_thread = None
        self.logger = logging.getLogger('pyguard.capture')
    
    def packet_callback(self, packet):
        """Callback function for each captured packet.
        
        Args:
            packet: The captured packet
        """
        try:
            self.analyzer.analyze_packet(packet)
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def capture_packets(self):
        """Capture packets using Scapy's sniff function."""
        try:
            self.logger.info(f"Starting packet capture on interface {self.interface}")
            sniff(iface=self.interface, prn=self.packet_callback, filter=self.packet_filter, store=0)
        except Exception as e:
            self.logger.error(f"Error in packet capture: {e}")
            self.running = False
    
    def start(self):
        """Start packet capture in a separate thread."""
        if self.running:
            self.logger.warning("Packet capture already running")
            return
        
        self.running = True
        self.capture_thread = threading.Thread(target=self.capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        self.logger.info("Packet capture thread started")
    
    def stop(self):
        """Stop packet capture."""
        if not self.running:
            return
        
        self.running = False
        # Scapy's sniff function doesn't have a clean way to stop it from another thread
        # We'll need to wait for the thread to exit naturally or use OS-specific methods
        if self.capture_thread and self.capture_thread.is_alive():
            self.logger.info("Waiting for packet capture thread to terminate...")
            self.capture_thread.join(timeout=3)
            if self.capture_thread.is_alive():
                self.logger.warning("Packet capture thread did not terminate gracefully")
        
        self.logger.info("Packet capture stopped")
    
    def is_running(self):
        """Check if packet capture is running.
        
        Returns:
            bool: True if running, False otherwise
        """
        return self.running and (self.capture_thread and self.capture_thread.is_alive())