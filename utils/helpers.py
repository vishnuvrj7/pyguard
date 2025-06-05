"""
Helpers Module

This module provides helper functions for the PyGuard IDS.
"""

import socket
import struct
import time
import platform
import subprocess
import re
from scapy.all import conf

def get_default_interface():
    """Get the default network interface.
    
    Returns:
        str: Default interface name
    """
    return conf.iface

def get_local_ip():
    """Get the local IP address.
    
    Returns:
        str: Local IP address
    """
    try:
        # Create a socket to determine the local IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def ip_to_int(ip_address):
    """Convert an IP address to an integer.
    
    Args:
        ip_address (str): IP address
    
    Returns:
        int: Integer representation of the IP address
    """
    return struct.unpack("!I", socket.inet_aton(ip_address))[0]

def int_to_ip(ip_int):
    """Convert an integer to an IP address.
    
    Args:
        ip_int (int): Integer representation of an IP address
    
    Returns:
        str: IP address
    """
    return socket.inet_ntoa(struct.pack("!I", ip_int))

def is_private_ip(ip_address):
    """Check if an IP address is private.
    
    Args:
        ip_address (str): IP address
    
    Returns:
        bool: True if private, False otherwise
    """
    # Convert IP to integer for range comparison
    ip_int = ip_to_int(ip_address)
    
    # Check private IP ranges
    private_ranges = [
        (ip_to_int("10.0.0.0"), ip_to_int("10.255.255.255")),
        (ip_to_int("172.16.0.0"), ip_to_int("172.31.255.255")),
        (ip_to_int("192.168.0.0"), ip_to_int("192.168.255.255")),
        (ip_to_int("127.0.0.0"), ip_to_int("127.255.255.255"))
    ]
    
    for start, end in private_ranges:
        if start <= ip_int <= end:
            return True
    
    return False

def get_timestamp():
    """Get current timestamp.
    
    Returns:
        float: Current timestamp
    """
    return time.time()

def format_timestamp(timestamp):
    """Format a timestamp as a human-readable string.
    
    Args:
        timestamp (float): Timestamp
    
    Returns:
        str: Formatted timestamp
    """
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))

def get_system_info():
    """Get system information.
    
    Returns:
        dict: System information
    """
    return {
        'platform': platform.platform(),
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'hostname': socket.gethostname(),
        'ip_address': get_local_ip()
    }

def ping(host):
    """Ping a host to check if it's reachable.
    
    Args:
        host (str): Host to ping
    
    Returns:
        bool: True if reachable, False otherwise
    """
    # Determine the ping command based on the platform
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', host]
    
    try:
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except Exception:
        return False

def is_valid_ip(ip_address):
    """Check if a string is a valid IP address.
    
    Args:
        ip_address (str): String to check
    
    Returns:
        bool: True if valid IP address, False otherwise
    """
    pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    match = re.match(pattern, ip_address)
    
    if not match:
        return False
    
    for i in range(1, 5):
        octet = int(match.group(i))
        if octet < 0 or octet > 255:
            return False
    
    return True

def is_valid_port(port):
    """Check if a value is a valid port number.
    
    Args:
        port: Value to check
    
    Returns:
        bool: True if valid port number, False otherwise
    """
    try:
        port_int = int(port)
        return 0 <= port_int <= 65535
    except (ValueError, TypeError):
        return False