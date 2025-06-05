#!/usr/bin/env python3
"""
PyGuard - A Simple Intrusion Detection System

This is the main entry point for the PyGuard IDS. It initializes the system,
starts packet capture, and begins monitoring network traffic for suspicious activities.
"""

import argparse
import sys
import time
from core.packet_capture import PacketCapture
from core.analyzer import TrafficAnalyzer
from core.detector import RuleBasedDetector
from core.alert import AlertManager
from config.settings import load_settings
from utils.logger import setup_logging

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='PyGuard - A Simple Intrusion Detection System')
    parser.add_argument('-i', '--interface', help='Network interface to monitor')
    parser.add_argument('-c', '--config', default='config/settings.py', help='Path to configuration file')
    parser.add_argument('-l', '--log', default='info', choices=['debug', 'info', 'warning', 'error', 'critical'],
                        help='Logging level')
    parser.add_argument('-o', '--output', help='Output file for alerts')
    parser.add_argument('-t', '--timeout', type=int, default=0, help='Monitoring timeout in seconds (0 for indefinite)')
    return parser.parse_args()

def main():
    """Main function to start the IDS."""
    args = parse_arguments()
    
    # Setup logging
    logger = setup_logging(args.log, args.output)
    logger.info("Starting PyGuard IDS...")
    
    try:
        # Load settings
        settings = load_settings(args.config)
        
        # Override settings with command line arguments if provided
        if args.interface:
            settings['interface'] = args.interface
        
        # Initialize components
        alert_manager = AlertManager(settings)
        detector = RuleBasedDetector(settings, alert_manager)
        analyzer = TrafficAnalyzer(settings, detector)
        packet_capture = PacketCapture(settings, analyzer)
        
        # Start monitoring
        logger.info(f"Monitoring network traffic on interface {settings['interface']}")
        packet_capture.start()
        
        # Run until timeout or keyboard interrupt
        if args.timeout > 0:
            time.sleep(args.timeout)
            packet_capture.stop()
        else:
            # Keep the main thread alive
            while packet_capture.is_running():
                time.sleep(1)
                
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received. Shutting down...")
        if 'packet_capture' in locals():
            packet_capture.stop()
    except Exception as e:
        logger.error(f"Error in main: {e}")
        if 'packet_capture' in locals():
            packet_capture.stop()
        return 1
    
    logger.info("PyGuard IDS shutdown complete.")
    return 0

if __name__ == "__main__":
    sys.exit(main())