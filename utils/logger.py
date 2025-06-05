"""
Logger Module

This module provides logging functionality for the PyGuard IDS.
"""

import logging
import os
from logging.handlers import RotatingFileHandler
import sys

def setup_logging(log_level='info', log_file=None):
    """Set up logging for the application.
    
    Args:
        log_level (str): Logging level (debug, info, warning, error, critical)
        log_file (str, optional): Path to log file
    
    Returns:
        logging.Logger: Configured logger
    """
    # Convert string log level to logging constant
    level_map = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'critical': logging.CRITICAL
    }
    level = level_map.get(log_level.lower(), logging.INFO)
    
    # Create logger
    logger = logging.getLogger('pyguard')
    logger.setLevel(level)
    
    # Remove existing handlers
    for handler in logger.handlers[:]:  
        logger.removeHandler(handler)
    
    # Create formatters
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # Create file handler if log file specified
    if log_file:
        # Create directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Create rotating file handler (10 MB max size, 5 backup files)
        file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
        file_handler.setLevel(level)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger

def get_logger(name):
    """Get a logger with the specified name.
    
    Args:
        name (str): Logger name
    
    Returns:
        logging.Logger: Logger instance
    """
    return logging.getLogger(f'pyguard.{name}')