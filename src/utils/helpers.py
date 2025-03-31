"""
Helper utilities for the Log Analysis & Monitoring System.
"""
import os
import yaml
import logging
import sys
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

# Get the project root directory (for absolute path resolution)
PROJECT_ROOT = Path(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

def load_config(config_path='config/config.yaml'):
    """
    Load configuration from a YAML file.
    
    Args:
        config_path (str): Path to the configuration file
        
    Returns:
        dict: Configuration data
    """
    try:
        # Handle both absolute and relative paths
        if not os.path.isabs(config_path):
            config_path = os.path.join(PROJECT_ROOT, config_path)
            
        with open(config_path, 'r') as file:
            return yaml.safe_load(file)
    except Exception as e:
        logger.error(f"Failed to load configuration from {config_path}: {str(e)}")
        raise

def setup_logging(log_dir='logs', log_level=logging.INFO):
    """
    Configure logging for the application.
    
    Args:
        log_dir (str): Directory to store log files
        log_level (int): Logging level
        
    Returns:
        logging.Logger: Configured logger
    """
    # Ensure log directory exists
    if not os.path.isabs(log_dir):
        log_dir = os.path.join(PROJECT_ROOT, log_dir)
    
    os.makedirs(log_dir, exist_ok=True)
    
    # Generate log filename with timestamp
    log_file = os.path.join(log_dir, f"app_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    
    # Configure logging
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Reduce verbosity of third-party libraries
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('matplotlib').setLevel(logging.WARNING)
    
    return logging.getLogger(__name__)

def load_patterns(patterns_path='config/patterns.yaml'):
    """
    Load regex patterns from a YAML file.
    
    Args:
        patterns_path (str): Path to the patterns file
        
    Returns:
        dict: Pattern data
    """
    try:
        # Handle both absolute and relative paths
        if not os.path.isabs(patterns_path):
            patterns_path = os.path.join(PROJECT_ROOT, patterns_path)
            
        with open(patterns_path, 'r') as file:
            return yaml.safe_load(file)
    except Exception as e:
        logger.error(f"Failed to load patterns from {patterns_path}: {str(e)}")
        # Return empty dict instead of raising to avoid crashes
        return {}

def get_log_files(log_dir, file_pattern=None):
    """
    Get a list of log files in a directory.
    
    Args:
        log_dir (str): Directory containing log files
        file_pattern (str, optional): Glob pattern to filter files
        
    Returns:
        list: List of log file paths
    """
    # Handle both absolute and relative paths
    if not os.path.isabs(log_dir):
        log_dir = os.path.join(PROJECT_ROOT, log_dir)
        
    if not os.path.exists(log_dir):
        logger.error(f"Log directory does not exist: {log_dir}")
        return []
    
    log_dir_path = Path(log_dir)
    
    if file_pattern:
        return list(log_dir_path.glob(file_pattern))
    else:
        return list(log_dir_path.glob("*.log"))

def ensure_dir_exists(directory):
    """
    Ensure that a directory exists, creating it if necessary.
    
    Args:
        directory (str): Path to the directory
    """
    # Handle both absolute and relative paths
    if not os.path.isabs(directory):
        directory = os.path.join(PROJECT_ROOT, directory)
        
    os.makedirs(directory, exist_ok=True)

def get_timestamp():
    """
    Get a formatted timestamp for the current time.
    
    Returns:
        str: Formatted timestamp
    """
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
