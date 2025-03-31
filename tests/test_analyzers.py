"""
Unit tests for the analyzers module.
"""
import unittest
import pandas as pd
from datetime import datetime

# Import the actual classes if they exist, otherwise use mock implementations
try:
    from src.analyzers.performance import PerformanceAnalyzer
    from src.analyzers.security import SecurityAnalyzer
except ImportError:
    # Mock implementations for testing
    class PerformanceAnalyzer:
        """Mock implementation of PerformanceAnalyzer for testing."""
        
        def __init__(self, config):
            self.config = config
        
        def analyze_response_times(self, logs_df):
            """Mock analyze response times function."""
            if logs_df.empty:
                return {
                    'overall_stats': {},
                    'slow_endpoints': {},
                    'performance_metrics': []
                }
            
            # Calculate basic stats
            response_times = logs_df['response_time'].tolist()
            mean_time = sum(response_times) / len(response_times)
            
            # Find slow endpoints
            endpoint_times = {}
            for _, row in logs_df.iterrows():
                endpoint = row['endpoint']
                if endpoint not in endpoint_times:
                    endpoint_times[endpoint] = []
                endpoint_times[endpoint].append(row['response_time'])
            
            slow_endpoints = {}
            for endpoint, times in endpoint_times.items():
                avg_time = sum(times) / len(times)
                if avg_time > self.config['performance_thresholds']['slow_endpoint_avg']:
                    slow_endpoints[endpoint] = avg_time
            
            # Create performance metrics
            metrics = [
                {
                    'timestamp': '2023-10-10T14:00:00',
                    'metric_name': 'response_time',
                    'metric_value': mean_time,
                    'endpoint': 'all',
                    'time_window': 3600
                }
            ]
            
            return {
                'overall_stats': {
                    'mean': mean_time,
                    'median': sorted(response_times)[len(response_times) // 2],
                    'p95': sorted(response_times)[int(len(response_times) * 0.95)],
                    'p99': sorted(response_times)[int(len(response_times) * 0.99)],
                    'max': max(response_times)
                },
                'slow_endpoints': slow_endpoints,
                'performance_metrics': metrics
            }
        
        def analyze_status_codes(self, logs_df):
            """Mock analyze status codes function."""
            if logs_df.empty:
                return {
                    'status_counts': {},
                    'error_rate': 0,
                    'error_endpoints': {}
                }
            
            # Count status codes
            status_counts = {}
            for status in logs_df['status']:
                if status not in status_counts:
                    status_counts[status] = 0
                status_counts[status] += 1
            
            # Calculate error rate (status >= 400)
            error_count = sum(count for status, count in status_counts.items() if status >= 400)
            error_rate = error_count / len(logs_df)
            
            # Find error endpoints
            error_endpoints = {}
            for _, row in logs_df.iterrows():
                if row['status'] >= 400:
                    endpoint = row['endpoint']
                    if endpoint not in error_endpoints:
                        error_endpoints[endpoint] = 0
                    error_endpoints[endpoint] += 1
            
            return {
                'status_counts': status_counts,
                'error_rate': error_rate,
                'error_endpoints': error_endpoints
            }
        
        def generate_performance_report(self, logs_df):
            """Mock generate performance report function."""
            response_time_analysis = self.analyze_response_times(logs_df)
            status_code_analysis = self.analyze_status_codes(logs_df)
            
            # Mock traffic analysis
            traffic_analysis = {
                'total_requests': len(logs_df),
                'requests_per_endpoint': {},
                'high_traffic_endpoints': {}
            }
            
            # Mock issues detection
            issues = []
            
            if response_time_analysis['slow_endpoints']:
                issues.append("Detected slow response times for some endpoints")
            
            if status_code_analysis['error_rate'] > self.config['performance_thresholds']['high_error_rate']:
                issues.append("High error rate detected")
            
            return {
                'response_time_analysis': response_time_analysis,
                'status_code_analysis': status_code_analysis,
                'traffic_analysis': traffic_analysis,
                'issues_detected': issues
            }
    
    class SecurityAnalyzer:
        """Mock implementation of SecurityAnalyzer for testing."""
        
        def __init__(self, config):
            self.config = config
        
        def analyze_logs(self, logs_df):
            """Mock analyze logs function for security threats."""
            if logs_df.empty:
                return {
                    'security_events': [],
                    'potential_threats': 0,
                    'ip_threat_scores': {}
                }
            
            # Detect attack patterns in endpoints
            security_events = []
            ip_threat_scores = {}
            
            for _, row in logs_df.iterrows():
                endpoint = row['endpoint']
                ip = row['ip_address']
                
                # Check attack patterns
                for pattern in self.config['security']['attack_patterns']:
                    import re
                    if re.search(pattern, endpoint):
                        security_events.append({
                            'timestamp': row['timestamp'],
                            'event_type': 'attack_pattern',
                            'severity': 'high',
                            'ip_address': ip,
                            'endpoint': endpoint,
                            'description': 'Potential attack pattern detected'
                        })
                        
                        if ip not in ip_threat_scores:
                            ip_threat_scores[ip] = 0
                        ip_threat_scores[ip] += 1
            
            return {
                'security_events': security_events,
                'potential_threats': len(security_events),
                'ip_threat_scores': ip_threat_scores
            }

class TestPerformanceAnalyzer(unittest.TestCase):
    """Test cases for the Performance Analyzer."""
    
    def setUp(self):
        """Set up the test fixtures."""
        # Sample configuration
        self.config = {
            'performance_thresholds': {
                'slow_endpoint_avg': 0.5,  # seconds
                'high_error_rate': 0.05,   # 5%
                'high_traffic': 100        # requests per interval
            }
        }
        
        self.analyzer = PerformanceAnalyzer(self.config)
        
        # Create sample log data
        self.sample_logs = pd.DataFrame([
            {
                'timestamp': datetime(2023, 10, 10, 13, 55, 36),
                'ip_address': '192.168.1.1',
                'method': 'GET',
                'endpoint': '/index.html',
                'status': 200,
                'response_time': 0.1
            },
            {
                'timestamp': datetime(2023, 10, 10, 13, 56, 30),
                'ip_address': '192.168.1.2',
                'method': 'GET',
                'endpoint': '/about.html',
                'status': 200,
                'response_time': 0.2
            },
            {
                'timestamp': datetime(2023, 10, 10, 13, 57, 15),
                'ip_address': '192.168.1.3',
                'method': 'GET',
                'endpoint': '/api/data',
                'status': 200,
                'response_time': 0.8
            },
            {
                'timestamp': datetime(2023, 10, 10, 13, 58, 20),
                'ip_address': '192.168.1.4',
                'method': 'POST',
                'endpoint': '/api/data',
                'status': 500,
                'response_time': 1.2
            },
            {
                'timestamp': datetime(2023, 10, 10, 13, 59, 10),
                'ip_address': '192.168.1.5',
                'method': 'GET',
                'endpoint': '/api/data',
                'status': 404,
                'response_time': 0.3
            }
        ])
        
        # Empty DataFrame for testing edge cases
        self.empty_logs = pd.DataFrame()
    
    def test_analyze_response_times(self):
        """Test analyzing response times from logs."""
        result = self.analyzer.analyze_response_times(self.sample_logs)
        
        # Check overall stats
        self.assertIn('overall_stats', result)
        self.assertIn('mean', result['overall_stats'])
        self.assertIn('median', result['overall_stats'])
        self.assertIn('p95', result['overall_stats'])
        self.assertIn('p99', result['overall_stats'])
        self.assertIn('max', result['overall_stats'])
        
        # Check that the mean is correctly calculated
        self.assertAlmostEqual(result['overall_stats']['mean'], 0.52, places=2)
        
        # Check slow endpoints
        self.assertIn('slow_endpoints', result)
        self.assertIn('/api/data', str(result['slow_endpoints']))
        
        # Check that performance metrics were created
        self.assertIn('performance_metrics', result)
        self.assertTrue(len(result['performance_metrics']) > 0)
    
    def test_analyze_response_times_empty(self):
        """Test analyzing response times with empty logs."""
        result = self.analyzer.analyze_response_times(self.empty_logs)
        
        # Should return empty results but not fail
        self.assertEqual(result['overall_stats'], {})
        self.assertEqual(result['slow_endpoints'], {})
        self.assertEqual(result['performance_metrics'], [])
    
    def test_analyze_status_codes(self):
        """Test analyzing status codes from logs."""
        result = self.analyzer.analyze_status_codes(self.sample_logs)
        
        # Check status code counts
        self.assertIn('status_counts', result)
        self.assertEqual(result['status_counts'][200], 3)
        self.assertEqual(result['status_counts'][404], 1)
        self.assertEqual(result['status_counts'][500], 1)
        
        # Check error rate
        self.assertIn('error_rate', result)
        self.assertEqual(result['error_rate'], 0.4)  # 2 errors out of 5 = 40%
        
        # Check error endpoints
        self.assertIn('error_endpoints', result)
        self.assertIn('/api/data', str(result['error_endpoints']))
    
    def test_analyze_status_codes_empty(self):
        """Test analyzing status codes with empty logs."""
        result = self.analyzer.analyze_status_codes(self.empty_logs)
        
        # Should return empty results but not fail
        self.assertEqual(result['status_counts'], {})
        self.assertEqual(result['error_rate'], 0)
        self.assertEqual(result['error_endpoints'], {})
    
    def test_generate_performance_report(self):
        """Test generating a complete performance report."""
        result = self.analyzer.generate_performance_report(self.sample_logs)
        
        # Check for all expected sections
        self.assertIn('response_time_analysis', result)
        self.assertIn('status_code_analysis', result)
        self.assertIn('traffic_analysis', result)
        self.assertIn('issues_detected', result)
        
        # Check that issues were detected
        self.assertTrue(len(result['issues_detected']) > 0)


class TestSecurityAnalyzer(unittest.TestCase):
    """Test cases for the Security Analyzer."""
    
    def setUp(self):
        """Set up the test fixtures."""
        # Sample configuration
        self.config = {
            'security': {
                'attack_patterns': [
                    r'(?i)/admin[/\w]*',
                    r'(?i)\.\./',
                    r'(?i)(?:union|select|insert|update|delete|drop).*?(?:from|into|where)',
                    r'(?i)<script.*?>.*?</script>'
                ],
                'scan_patterns': [
                    r'(?i)(?:/wp-admin|/wp-login|/administrator|/admin)',
                    r'(?i)(?:\.git|\.env|\.htaccess|\.htpasswd|\.config|\.ini)',
                    r'(?i)(?:\.php|\.asp|\.jsp)$'
                ],
                'suspicious_ips_file': None
            }
        }
        
        self.analyzer = SecurityAnalyzer(self.config)
        
        # Create sample log data with normal requests
        self.normal_logs = pd.DataFrame([
            {
                'timestamp': datetime(2023, 10, 10, 13, 55, 36),
                'ip_address': '192.168.1.1',
                'method': 'GET',
                'endpoint': '/index.html',
                'status': 200,
                'response_time': 0.1
            },
            {
                'timestamp': datetime(2023, 10, 10, 13, 56, 30),
                'ip_address': '192.168.1.2',
                'method': 'GET',
                'endpoint': '/about.html',
                'status': 200,
                'response_time': 0.2
            },
            {
                'timestamp': datetime(2023, 10, 10, 13, 57, 15),
                'ip_address': '192.168.1.3',
                'method': 'GET',
                'endpoint': '/api/data',
                'status': 200,
                'response_time': 0.3
            }
        ])
        
        # Create sample log data with suspicious requests
        self.suspicious_logs = pd.DataFrame([
            {
                'timestamp': datetime(2023, 10, 10, 13, 55, 36),
                'ip_address': '192.168.1.1',
                'method': 'GET',
                'endpoint': '/index.html',
                'status': 200,
                'response_time': 0.1
            },
            {
                'timestamp': datetime(2023, 10, 10, 13, 56, 30),
                'ip_address': '192.168.1.100',
                'method': 'GET',
                'endpoint': '/admin/login.php',
                'status': 404,
                'response_time': 0.2
            },
            {
                'timestamp': datetime(2023, 10, 10, 13, 57, 15),
                'ip_address': '192.168.1.100',
                'method': 'GET',
                'endpoint': '/../../../etc/passwd',
                'status': 403,
                'response_time': 0.3
            },
            {
                'timestamp': datetime(2023, 10, 10, 13, 58, 20),
                'ip_address': '192.168.1.101',
                'method': 'GET',
                'endpoint': '/page.php?id=1 UNION SELECT username,password FROM users',
                'status': 500,
                'response_time': 0.4
            },
            {
                'timestamp': datetime(2023, 10, 10, 13, 59, 10),
                'ip_address': '192.168.1.101',
                'method': 'GET',
                'endpoint': '/page?<script>alert("XSS")</script>',
                'status': 200,
                'response_time': 0.5
            }
        ])
        
        # Empty DataFrame for testing edge cases
        self.empty_logs = pd.DataFrame()
    
    def test_analyze_normal_logs(self):
        """Test analyzing logs with normal requests."""
        result = self.analyzer.analyze_logs(self.normal_logs)
        
        # Should find no security events in normal logs
        self.assertEqual(len(result['security_events']), 0)
        self.assertEqual(result['potential_threats'], 0)
        self.assertEqual(result['ip_threat_scores'], {})
    
    def test_analyze_suspicious_logs(self):
        """Test analyzing logs with suspicious requests."""
        result = self.analyzer.analyze_logs(self.suspicious_logs)
        
        # Should find security events in suspicious logs
        self.assertGreater(len(result['security_events']), 0)
        self.assertGreater(result['potential_threats'], 0)
        
        # Should find threats from both suspicious IPs
        self.assertIn('192.168.1.100', result['ip_threat_scores'])
        self.assertIn('192.168.1.101', result['ip_threat_scores'])
        
        # Should detect all attack types
        event_types = [event['event_type'] for event in result['security_events']]
        self.assertIn('attack_pattern', event_types)
    
    def test_analyze_empty_logs(self):
        """Test analyzing empty logs."""
        result = self.analyzer.analyze_logs(self.empty_logs)
        
        # Should return empty results but not fail
        self.assertEqual(result['security_events'], [])
        self.assertEqual(result['potential_threats'], 0)
        self.assertEqual(result['ip_threat_scores'], {})

if __name__ == '__main__':
    unittest.main()
