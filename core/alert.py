"""
Alert Manager Module

This module is responsible for generating, managing, and delivering alerts
when suspicious activities are detected.
"""

import logging
import json
import time
import os
from datetime import datetime

class AlertManager:
    """Class for managing and generating alerts."""
    
    def __init__(self, settings):
        """Initialize the alert manager.
        
        Args:
            settings (dict): Configuration settings
        """
        self.settings = settings
        self.logger = logging.getLogger('pyguard.alert')
        
        # Alert storage
        self.alerts = []
        
        # Alert file configuration
        self.alert_file = settings.get('alert_file', 'alerts.json')
        self.alert_log_enabled = settings.get('alert_log_enabled', True)
        
        # Create alert directory if it doesn't exist
        alert_dir = os.path.dirname(self.alert_file)
        if alert_dir and not os.path.exists(alert_dir):
            os.makedirs(alert_dir)
        
        # Alert thresholds for rate limiting
        self.alert_thresholds = {
            'low': settings.get('low_alert_threshold', 10),
            'medium': settings.get('medium_alert_threshold', 5),
            'high': settings.get('high_alert_threshold', 1)
        }
        
        # Alert counters for rate limiting
        self.alert_counters = {}
        
        # Last alert time for rate limiting
        self.last_alert_time = {}
    
    def generate_alert(self, alert_data):
        """Generate an alert based on the provided data.
        
        Args:
            alert_data (dict): Data for the alert
        """
        # Add timestamp to alert
        alert_data['timestamp'] = datetime.now().isoformat()
        
        # Check for rate limiting
        if self.should_rate_limit(alert_data):
            return
        
        # Log the alert
        severity = alert_data.get('severity', 'low').upper()
        message = alert_data.get('message', 'Unknown alert')
        self.logger.warning(f"[{severity}] {message}")
        
        # Store the alert
        self.alerts.append(alert_data)
        
        # Write to alert file if enabled
        if self.alert_log_enabled:
            self.write_alert_to_file(alert_data)
        
        # Execute any configured alert actions
        self.execute_alert_actions(alert_data)
    
    def should_rate_limit(self, alert_data):
        """Check if an alert should be rate limited.
        
        Args:
            alert_data (dict): Data for the alert
        
        Returns:
            bool: True if the alert should be rate limited, False otherwise
        """
        # Extract key information for rate limiting
        alert_type = alert_data.get('type', 'unknown')
        src_ip = alert_data.get('src_ip', 'unknown')
        severity = alert_data.get('severity', 'low')
        
        # Create a key for this specific alert type and source
        alert_key = f"{alert_type}:{src_ip}"
        
        # Get current time
        current_time = time.time()
        
        # Initialize counters if this is a new alert key
        if alert_key not in self.alert_counters:
            self.alert_counters[alert_key] = 0
            self.last_alert_time[alert_key] = current_time
        
        # Check if we've exceeded the threshold for this severity
        threshold = self.alert_thresholds.get(severity, 10)
        time_window = self.settings.get('alert_time_window', 60)  # seconds
        
        # Reset counter if time window has passed
        if current_time - self.last_alert_time[alert_key] > time_window:
            self.alert_counters[alert_key] = 0
            self.last_alert_time[alert_key] = current_time
        
        # Increment counter
        self.alert_counters[alert_key] += 1
        
        # Check if we should rate limit
        if self.alert_counters[alert_key] > threshold:
            # Only log rate limiting once per time window
            if self.alert_counters[alert_key] == threshold + 1:
                self.logger.info(f"Rate limiting alerts for {alert_key} (exceeded {threshold} alerts in {time_window} seconds)")
            return True
        
        return False
    
    def write_alert_to_file(self, alert_data):
        """Write an alert to the alert file.
        
        Args:
            alert_data (dict): Data for the alert
        """
        try:
            # Read existing alerts if file exists
            alerts = []
            if os.path.exists(self.alert_file):
                with open(self.alert_file, 'r') as f:
                    try:
                        alerts = json.load(f)
                    except json.JSONDecodeError:
                        self.logger.error(f"Error decoding JSON from alert file {self.alert_file}")
                        alerts = []
            
            # Add new alert
            alerts.append(alert_data)
            
            # Write back to file
            with open(self.alert_file, 'w') as f:
                json.dump(alerts, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error writing alert to file: {e}")
    
    def execute_alert_actions(self, alert_data):
        """Execute any configured actions for an alert.
        
        Args:
            alert_data (dict): Data for the alert
        """
        # Get severity-specific actions
        severity = alert_data.get('severity', 'low')
        actions = self.settings.get(f"{severity}_alert_actions", [])
        
        # Execute each action
        for action in actions:
            action_type = action.get('type')
            if action_type == 'email':
                self.send_email_alert(alert_data, action)
            elif action_type == 'syslog':
                self.send_syslog_alert(alert_data, action)
            elif action_type == 'webhook':
                self.send_webhook_alert(alert_data, action)
            elif action_type == 'command':
                self.execute_command_alert(alert_data, action)
    
    def send_email_alert(self, alert_data, action_config):
        """Send an email alert.
        
        Args:
            alert_data (dict): Data for the alert
            action_config (dict): Configuration for the email action
        """
        # This is a placeholder for email alert functionality
        # In a real implementation, this would use SMTP to send an email
        self.logger.info(f"Would send email alert to {action_config.get('recipient')}")
    
    def send_syslog_alert(self, alert_data, action_config):
        """Send a syslog alert.
        
        Args:
            alert_data (dict): Data for the alert
            action_config (dict): Configuration for the syslog action
        """
        # This is a placeholder for syslog alert functionality
        # In a real implementation, this would send to a syslog server
        self.logger.info(f"Would send syslog alert to {action_config.get('server')}")
    
    def send_webhook_alert(self, alert_data, action_config):
        """Send a webhook alert.
        
        Args:
            alert_data (dict): Data for the alert
            action_config (dict): Configuration for the webhook action
        """
        # This is a placeholder for webhook alert functionality
        # In a real implementation, this would make an HTTP request
        self.logger.info(f"Would send webhook alert to {action_config.get('url')}")
    
    def execute_command_alert(self, alert_data, action_config):
        """Execute a command for an alert.
        
        Args:
            alert_data (dict): Data for the alert
            action_config (dict): Configuration for the command action
        """
        # This is a placeholder for command execution functionality
        # In a real implementation, this would execute a system command
        self.logger.info(f"Would execute command: {action_config.get('command')}")
    
    def get_recent_alerts(self, count=10):
        """Get the most recent alerts.
        
        Args:
            count (int): Number of alerts to retrieve
        
        Returns:
            list: Recent alerts
        """
        return self.alerts[-count:]
    
    def get_alerts_by_severity(self, severity):
        """Get alerts filtered by severity.
        
        Args:
            severity (str): Severity level to filter by
        
        Returns:
            list: Filtered alerts
        """
        return [alert for alert in self.alerts if alert.get('severity') == severity]
    
    def get_alerts_by_type(self, alert_type):
        """Get alerts filtered by type.
        
        Args:
            alert_type (str): Alert type to filter by
        
        Returns:
            list: Filtered alerts
        """
        return [alert for alert in self.alerts if alert.get('type') == alert_type]