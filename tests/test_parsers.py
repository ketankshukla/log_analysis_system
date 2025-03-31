"""
Unit tests for the log parsers module.
"""
import unittest
import os
from datetime import datetime
from pathlib import Path
from src.parsers.apache_parser import ApacheLogParser

class TestApacheLogParser(unittest.TestCase):
    """Test cases for the Apache log parser."""
    
    def setUp(self):
        """Set up the test fixtures."""
        self.parser = ApacheLogParser()
        
        # Sample log lines for different formats
        self.common_log_line = '192.168.1.1 - john [10/Oct/2023:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326'
        self.combined_log_line = '192.168.1.1 - john [10/Oct/2023:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "http://example.com/start.html" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
        self.combined_time_log_line = '192.168.1.1 - john [10/Oct/2023:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "http://example.com/start.html" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" 0.005'
        self.error_log_line = '[Wed Oct 11 14:32:52 2023] [error] [client 192.168.1.1] File does not exist: /var/www/html/favicon.ico'
        
        # Invalid log lines
        self.invalid_log_line = 'This is not a valid log line'
        self.empty_log_line = ''
    
    def test_parse_common_log_format(self):
        """Test parsing a log line in Common Log Format."""
        result = self.parser.parse_line(self.common_log_line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['ip_address'], '192.168.1.1')
        self.assertEqual(result['user'], 'john')
        self.assertEqual(result['method'], 'GET')
        self.assertEqual(result['endpoint'], '/index.html')
        self.assertEqual(result['status'], 200)
        self.assertEqual(result['bytes_sent'], 2326)
        self.assertEqual(result['log_format'], 'common')
        self.assertIsInstance(result['timestamp'], datetime)
    
    def test_parse_combined_log_format(self):
        """Test parsing a log line in Combined Log Format."""
        result = self.parser.parse_line(self.combined_log_line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['ip_address'], '192.168.1.1')
        self.assertEqual(result['user'], 'john')
        self.assertEqual(result['method'], 'GET')
        self.assertEqual(result['endpoint'], '/index.html')
        self.assertEqual(result['status'], 200)
        self.assertEqual(result['bytes_sent'], 2326)
        self.assertEqual(result['referrer'], 'http://example.com/start.html')
        self.assertEqual(result['user_agent'], 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
        self.assertEqual(result['log_format'], 'combined')
        self.assertIsInstance(result['timestamp'], datetime)
    
    def test_parse_combined_time_log_format(self):
        """Test parsing a log line in Combined Log Format with response time."""
        result = self.parser.parse_line(self.combined_time_log_line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['ip_address'], '192.168.1.1')
        self.assertEqual(result['user'], 'john')
        self.assertEqual(result['method'], 'GET')
        self.assertEqual(result['endpoint'], '/index.html')
        self.assertEqual(result['status'], 200)
        self.assertEqual(result['bytes_sent'], 2326)
        self.assertEqual(result['referrer'], 'http://example.com/start.html')
        self.assertEqual(result['user_agent'], 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
        self.assertEqual(result['response_time'], 0.005)
        self.assertEqual(result['log_format'], 'combined_time')
        self.assertIsInstance(result['timestamp'], datetime)
    
    def test_parse_error_log_format(self):
        """Test parsing a log line in Error Log Format."""
        result = self.parser.parse_line(self.error_log_line, log_type='error')
        
        self.assertIsNotNone(result)
        self.assertEqual(result['log_type'], 'error')
        self.assertEqual(result['module'], 'error')
        self.assertEqual(result['client'], '192.168.1.1')
        self.assertEqual(result['message'], 'File does not exist: /var/www/html/favicon.ico')
        self.assertIsInstance(result['timestamp'], datetime)
    
    def test_parse_invalid_log_line(self):
        """Test parsing an invalid log line."""
        result = self.parser.parse_line(self.invalid_log_line)
        self.assertIsNone(result)
    
    def test_parse_empty_log_line(self):
        """Test parsing an empty log line."""
        result = self.parser.parse_line(self.empty_log_line)
        self.assertIsNone(result)
    
    def test_detect_format_sample_file(self):
        """Test detecting the format of the sample log file."""
        # Get the path to the sample log file
        script_dir = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        sample_log_path = script_dir / "data" / "logs" / "sample_apache.log"
        
        # Only run the test if the sample log file exists
        if sample_log_path.exists():
            detected_format = self.parser.detect_format(sample_log_path)
            self.assertIn(detected_format, ['common', 'combined', 'combined_time', 'error'])
        else:
            self.skipTest(f"Sample log file not found: {sample_log_path}")
    
    def test_detect_format_nonexistent_file(self):
        """Test detecting the format of a nonexistent file."""
        nonexistent_file = "nonexistent_file.log"
        
        # Use a try-except block to handle the case when the file doesn't exist
        try:
            detected_format = self.parser.detect_format(nonexistent_file)
            # If no exception was raised, check that the format is 'unknown'
            self.assertEqual(detected_format, 'unknown')
        except FileNotFoundError:
            # If a FileNotFoundError was raised, that's also acceptable
            pass

if __name__ == '__main__':
    unittest.main()
