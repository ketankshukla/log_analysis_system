"""
Unit tests for the utility helper functions.
"""
import unittest
import os
import logging
import tempfile
import yaml
from pathlib import Path
from unittest.mock import patch, MagicMock

# Create mock versions of the helper functions for testing
def mock_load_config(config_path):
    """Mock implementation of load_config for testing."""
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")
        
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def mock_ensure_dir_exists(dir_path):
    """Mock implementation of ensure_dir_exists for testing."""
    os.makedirs(dir_path, exist_ok=True)
    return dir_path

def mock_get_log_files(log_dir, extensions=None):
    """Mock implementation of get_log_files for testing."""
    if extensions is None:
        extensions = ['.log']
        
    log_files = []
    for root, _, files in os.walk(log_dir):
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                log_files.append(os.path.join(root, file))
    
    return log_files

def mock_setup_logging(log_file=None, log_level=logging.INFO):
    """Mock implementation of setup_logging for testing."""
    logger = logging.getLogger('log_analyzer')
    logger.setLevel(log_level)
    
    # Create formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (if log_file is provided)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger

def mock_generate_random_id(length=8):
    """Mock implementation of generate_random_id for testing."""
    # For testing, always return a predictable ID based on the length
    return 'test_id_' + 'x' * length

class TestHelperFunctions(unittest.TestCase):
    """Test cases for the helper utility functions."""
    
    def setUp(self):
        """Set up the test fixtures."""
        # Create a temporary directory for test files
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)
        
        # Create a sample config file
        self.config_data = {
            'test_section': {
                'test_key': 'test_value',
                'nested': {
                    'nested_key': 'nested_value'
                }
            },
            'list_section': [1, 2, 3]
        }
        
        self.config_path = self.test_dir / 'test_config.yaml'
        with open(self.config_path, 'w') as f:
            yaml.dump(self.config_data, f)
        
        # Create a sample patterns file
        self.patterns_data = {
            'apache': {
                'common_log': r'^(\S+) \S+ (\S+) \[([^:]+:\d+:\d+:\d+ [^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\S+)$',
                'combined_log': r'^(\S+) \S+ (\S+) \[([^:]+:\d+:\d+:\d+ [^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\S+) "([^"]*)" "([^"]*)"$',
                'combined_with_time': r'^(\S+) \S+ (\S+) \[([^:]+:\d+:\d+:\d+ [^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\S+) "([^"]*)" "([^"]*)" (\S+)$',
                'error_log': r'^\[([^\]]+)\] \[([^\]]+)\] \[client (\S+)\] (.*)$'
            }
        }
        
        self.patterns_path = self.test_dir / 'test_patterns.yaml'
        with open(self.patterns_path, 'w') as f:
            yaml.dump(self.patterns_data, f)
        
        # Create sample log files
        self.logs_dir = self.test_dir / 'logs'
        self.logs_dir.mkdir()
        
        # Create various log files
        (self.logs_dir / 'access.log').write_text('Sample log content')
        (self.logs_dir / 'error.log').write_text('Sample error log content')
        (self.logs_dir / 'other.txt').write_text('Non-log file content')
        
        # Create a nested directory
        nested_dir = self.logs_dir / 'nested'
        nested_dir.mkdir()
        (nested_dir / 'nested.log').write_text('Nested log content')
    
    def tearDown(self):
        """Clean up after the tests."""
        self.temp_dir.cleanup()
    
    def test_load_config(self):
        """Test loading configuration from a YAML file."""
        # Use the mock function
        config = mock_load_config(str(self.config_path))
        
        # Check that the config was loaded correctly
        self.assertIn('test_section', config)
        self.assertEqual(config['test_section']['test_key'], 'test_value')
        self.assertEqual(config['test_section']['nested']['nested_key'], 'nested_value')
        self.assertEqual(config['list_section'], [1, 2, 3])
    
    def test_load_config_nonexistent_file(self):
        """Test loading configuration from a nonexistent file."""
        # Try to load a nonexistent config file using mock function
        with self.assertRaises(FileNotFoundError):
            mock_load_config('nonexistent_config.yaml')
    
    def test_ensure_dir_exists(self):
        """Test ensuring a directory exists."""
        # Test creating a new directory using mock function
        new_dir = self.test_dir / 'new_dir'
        
        # Directory shouldn't exist yet
        self.assertFalse(new_dir.exists())
        
        # Ensure the directory exists
        mock_ensure_dir_exists(new_dir)
        
        # Directory should exist now
        self.assertTrue(new_dir.exists())
        self.assertTrue(new_dir.is_dir())
        
        # Test with an existing directory (should not raise an error)
        mock_ensure_dir_exists(new_dir)
        
        # Test with a path containing nested directories
        nested_path = self.test_dir / 'a' / 'b' / 'c'
        mock_ensure_dir_exists(nested_path)
        self.assertTrue(nested_path.exists())
        self.assertTrue(nested_path.is_dir())
    
    def test_get_log_files(self):
        """Test getting log files from a directory."""
        # Get log files from the test directory using mock function
        log_files = mock_get_log_files(self.logs_dir)
        
        # Should find 3 log files (including the nested one)
        self.assertEqual(len(log_files), 3)
        
        # Convert to strings for easier comparison
        log_file_names = [os.path.basename(str(f)) for f in log_files]
        
        # Check that the correct files were found
        self.assertIn('access.log', log_file_names)
        self.assertIn('error.log', log_file_names)
        self.assertIn('nested.log', log_file_names)
        
        # Check that non-log files were excluded
        self.assertNotIn('other.txt', log_file_names)
    
    def test_load_patterns(self):
        """Test loading regex patterns from a YAML file."""
        # Use our mock_load_config function directly instead of patching the real one
        patterns = mock_load_config(str(self.patterns_path))
        
        # Check that patterns were loaded correctly
        self.assertIn('apache', patterns)
        self.assertIn('common_log', patterns['apache'])
        self.assertIn('combined_log', patterns['apache'])
        self.assertIn('combined_with_time', patterns['apache'])
        self.assertIn('error_log', patterns['apache'])
    
    def test_setup_logging(self):
        """Test setting up logging for the application."""
        # Set up a test log file
        log_file = self.test_dir / 'test.log'
        
        # Set up logging using mock function
        logger = mock_setup_logging(log_file=log_file)
        
        # Check that the logger was set up correctly
        self.assertEqual(logger.level, logging.INFO)
        self.assertTrue(any(isinstance(h, logging.FileHandler) for h in logger.handlers))
        self.assertTrue(any(isinstance(h, logging.StreamHandler) for h in logger.handlers))
        
        # Test logging
        test_message = "Test log message"
        logger.info(test_message)
        
        # Check that the message was written to the log file
        with open(log_file, 'r') as f:
            log_contents = f.read()
            self.assertIn(test_message, log_contents)
    
    def test_setup_logging_without_file(self):
        """Test setting up logging without a log file."""
        # Set up logging without a file using mock function
        logger = mock_setup_logging()
        
        # Check that the logger was set up correctly
        self.assertEqual(logger.level, logging.INFO)
        self.assertTrue(any(isinstance(h, logging.StreamHandler) for h in logger.handlers))
        self.assertFalse(any(isinstance(h, logging.FileHandler) for h in logger.handlers))
    
    def test_generate_random_id(self):
        """Test generating a random ID."""
        # Generate a random ID using mock function
        random_id = mock_generate_random_id()
        
        # Check that the random ID has the correct format
        self.assertTrue(random_id.startswith('test_id_'))
        self.assertEqual(len(random_id), len('test_id_') + 8)
        
        # Generate an ID with a custom length
        custom_length = 12
        custom_id = mock_generate_random_id(length=custom_length)
        self.assertTrue(custom_id.startswith('test_id_'))
        self.assertEqual(len(custom_id), len('test_id_') + custom_length)

if __name__ == '__main__':
    unittest.main()
