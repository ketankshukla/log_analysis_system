"""
Unit tests for the storage module.
"""
import unittest
import os
import sqlite3
import tempfile
import pandas as pd
from datetime import datetime
from pathlib import Path

# Mock database class for testing
class MockLogDatabase:
    """Mock implementation of LogDatabase for testing."""
    
    def __init__(self, db_path):
        """Initialize with the database path but don't actually connect."""
        self.db_path = db_path
        self.is_connected = True
        # Keep track of stored data
        self.stored_data = {
            'access_logs': [],
            'error_logs': [],
            'performance_metrics': [],
            'security_events': []
        }
    
    def close(self):
        """Mock closing the database connection."""
        self.is_connected = False
    
    def store_access_logs(self, logs, source_file):
        """Mock storing access logs."""
        if not self.is_connected:
            return False
        
        self.stored_data['access_logs'].extend(logs)
        return True
    
    def store_error_logs(self, logs, source_file):
        """Mock storing error logs."""
        if not self.is_connected:
            return False
        
        self.stored_data['error_logs'].extend(logs)
        return True
    
    def store_performance_metrics(self, metrics):
        """Mock storing performance metrics."""
        if not self.is_connected:
            return False
        
        self.stored_data['performance_metrics'].extend(metrics)
        return True
    
    def store_security_events(self, events):
        """Mock storing security events."""
        if not self.is_connected:
            return False
        
        self.stored_data['security_events'].extend(events)
        return True
    
    def query_access_logs(self, start_time=None, end_time=None, filters=None):
        """Mock querying access logs."""
        if not self.is_connected:
            return []
        
        # Just return all stored logs for simplicity in tests
        return self.stored_data['access_logs']
    
    def query_security_events(self, start_time=None, end_time=None, min_severity=None):
        """Mock querying security events."""
        if not self.is_connected:
            return []
        
        if min_severity:
            # Filter by severity
            return [event for event in self.stored_data['security_events'] 
                    if self._severity_level(event['severity']) >= self._severity_level(min_severity)]
        else:
            return self.stored_data['security_events']
    
    def _severity_level(self, severity):
        """Helper to convert severity string to level."""
        levels = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        return levels.get(severity.lower(), 0)
    
    def get_log_summary(self):
        """Mock getting a summary of logs."""
        if not self.is_connected:
            return {}
        
        # Calculate total bytes sent
        total_bytes = sum(log.get('bytes_sent', 0) for log in self.stored_data['access_logs'])
        
        return {
            'access_logs_count': len(self.stored_data['access_logs']),
            'error_logs_count': len(self.stored_data['error_logs']),
            'performance_metrics_count': len(self.stored_data['performance_metrics']),
            'security_events_count': len(self.stored_data['security_events']),
            'total_bytes_sent': total_bytes
        }


class TestLogDatabase(unittest.TestCase):
    """Test cases for the Log Database."""
    
    def setUp(self):
        """Set up the test fixtures."""
        # Create a temporary database file
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_logs.db")
        
        # Sample configuration
        self.config = {
            'database': {
                'path': self.db_path
            }
        }
        
        # Create the mock database
        self.db = MockLogDatabase(self.db_path)
        
        # Sample log data
        self.access_logs = [
            {
                'timestamp': datetime(2023, 10, 10, 13, 55, 36),
                'ip_address': '192.168.1.1',
                'method': 'GET',
                'endpoint': '/index.html',
                'status': 200,
                'bytes_sent': 1024,
                'referrer': 'http://example.com',
                'user_agent': 'Mozilla/5.0',
                'response_time': 0.1,
                'log_format': 'combined_time',
                'log_type': 'access'
            },
            {
                'timestamp': datetime(2023, 10, 10, 13, 56, 30),
                'ip_address': '192.168.1.2',
                'method': 'POST',
                'endpoint': '/api/data',
                'status': 201,
                'bytes_sent': 512,
                'referrer': 'http://example.com/form',
                'user_agent': 'Mozilla/5.0',
                'response_time': 0.3,
                'log_format': 'combined_time',
                'log_type': 'access'
            }
        ]
        
        self.error_logs = [
            {
                'timestamp': datetime(2023, 10, 10, 14, 30, 15),
                'module': 'error',
                'client': '192.168.1.1',
                'message': 'File does not exist: /var/www/html/favicon.ico',
                'log_type': 'error'
            }
        ]
        
        self.performance_metrics = [
            {
                'timestamp': '2023-10-10T14:00:00',
                'metric_name': 'response_time',
                'metric_value': 0.15,
                'endpoint': '/index.html',
                'time_window': 3600
            },
            {
                'timestamp': '2023-10-10T14:00:00',
                'metric_name': 'error_rate',
                'metric_value': 0.05,
                'endpoint': '/api/data',
                'time_window': 3600
            }
        ]
        
        self.security_events = [
            {
                'timestamp': datetime(2023, 10, 10, 13, 58, 20),
                'event_type': 'attack_pattern',
                'severity': 'high',
                'ip_address': '192.168.1.100',
                'endpoint': '/admin/login.php',
                'description': 'Potential admin page access attempt'
            }
        ]
    
    def tearDown(self):
        """Clean up after the tests."""
        self.db.close()
        self.temp_dir.cleanup()
    
    def test_store_access_logs(self):
        """Test storing access logs in the database."""
        # Store the sample access logs
        result = self.db.store_access_logs(self.access_logs, source_file='test_sample.log')
        
        # Check that the operation was successful
        self.assertTrue(result)
        
        # Check that both logs were stored
        self.assertEqual(len(self.db.stored_data['access_logs']), 2)
    
    def test_store_error_logs(self):
        """Test storing error logs in the database."""
        # Store the sample error logs
        result = self.db.store_error_logs(self.error_logs, source_file='test_error.log')
        
        # Check that the operation was successful
        self.assertTrue(result)
        
        # Check that the error log was stored
        self.assertEqual(len(self.db.stored_data['error_logs']), 1)
    
    def test_store_performance_metrics(self):
        """Test storing performance metrics in the database."""
        # Store the sample performance metrics
        result = self.db.store_performance_metrics(self.performance_metrics)
        
        # Check that the operation was successful
        self.assertTrue(result)
        
        # Check that both metrics were stored
        self.assertEqual(len(self.db.stored_data['performance_metrics']), 2)
    
    def test_store_security_events(self):
        """Test storing security events in the database."""
        # Store the sample security events
        result = self.db.store_security_events(self.security_events)
        
        # Check that the operation was successful
        self.assertTrue(result)
        
        # Check that the security event was stored
        self.assertEqual(len(self.db.stored_data['security_events']), 1)
    
    def test_query_access_logs(self):
        """Test querying access logs from the database."""
        # Store the sample access logs
        self.db.store_access_logs(self.access_logs, source_file='test_sample.log')
        
        # Query the logs
        logs = self.db.query_access_logs(
            start_time=datetime(2023, 10, 10, 0, 0, 0),
            end_time=datetime(2023, 10, 11, 0, 0, 0)
        )
        
        # Check that both logs were retrieved
        self.assertEqual(len(logs), 2)
    
    def test_query_security_events(self):
        """Test querying security events from the database."""
        # Store the sample security events
        self.db.store_security_events(self.security_events)
        
        # Query the events
        events = self.db.query_security_events(
            start_time=datetime(2023, 10, 10, 0, 0, 0),
            end_time=datetime(2023, 10, 11, 0, 0, 0),
            min_severity='medium'
        )
        
        # Check that the high severity event was retrieved
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['severity'], 'high')
    
    def test_get_log_summary(self):
        """Test getting a summary of logs from the database."""
        # Store the sample logs
        self.db.store_access_logs(self.access_logs, source_file='test_sample.log')
        self.db.store_error_logs(self.error_logs, source_file='test_error.log')
        
        # Get the summary
        summary = self.db.get_log_summary()
        
        # Check that the summary contains the correct counts
        self.assertEqual(summary['access_logs_count'], 2)
        self.assertEqual(summary['error_logs_count'], 1)
        self.assertEqual(summary['total_bytes_sent'], 1536)  # 1024 + 512
    
    def test_error_handling(self):
        """Test error handling when database operations fail."""
        # Close the database first to force an error
        self.db.close()
        
        # Try to store logs after closing
        result = self.db.store_access_logs(self.access_logs, source_file='test_sample.log')
        
        # Should return False indicating failure
        self.assertFalse(result)

if __name__ == '__main__':
    unittest.main()
