"""
Performance analyzer for the Log Analysis & Monitoring System.
"""
import logging
import numpy as np
import pandas as pd
from datetime import datetime

logger = logging.getLogger(__name__)

class PerformanceAnalyzer:
    """
    Analyzes performance metrics from parsed logs.
    Identifies slow endpoints, high error rates, and other performance issues.
    """
    
    def __init__(self, config):
        """
        Initialize the performance analyzer.
        
        Args:
            config (dict): Configuration dictionary
        """
        self.config = config
        self.thresholds = config['performance_thresholds']
        logger.debug("Performance analyzer initialized")
    
    def analyze_response_times(self, logs_df):
        """
        Analyze response times from parsed logs.
        
        Args:
            logs_df (pandas.DataFrame): DataFrame containing parsed logs
            
        Returns:
            dict: Performance metrics and identified issues
        """
        if logs_df.empty or 'response_time' not in logs_df.columns:
            logger.warning("No response time data available for analysis")
            return {
                'overall_stats': {},
                'slow_endpoints': {},
                'performance_metrics': []
            }
        
        # Calculate overall statistics
        stats = {
            'mean': logs_df['response_time'].mean(),
            'median': logs_df['response_time'].median(),
            'p95': logs_df['response_time'].quantile(0.95),
            'p99': logs_df['response_time'].quantile(0.99),
            'max': logs_df['response_time'].max()
        }
        
        logger.info(f"Overall response time stats - Mean: {stats['mean']:.3f}s, "
                   f"95th percentile: {stats['p95']:.3f}s, Max: {stats['max']:.3f}s")
        
        # Analyze by endpoint
        if 'endpoint' in logs_df.columns:
            endpoint_stats = logs_df.groupby('endpoint').agg({
                'response_time': ['count', 'mean', 'median', 'max', 
                                 lambda x: np.percentile(x, 95) if len(x) > 0 else 0],
                'status': [lambda x: (x >= 400).sum() / len(x) if len(x) > 0 else 0]
            })
            
            # Flatten the column hierarchy
            endpoint_stats.columns = [
                'count', 'mean_time', 'median_time', 'max_time', 'p95_time', 'error_rate'
            ]
            
            # Identify slow endpoints
            slow_endpoints = endpoint_stats[
                endpoint_stats['mean_time'] > self.thresholds['slow_endpoint_avg']
            ]
            
            # Create performance metrics for storage
            performance_metrics = []
            current_time = datetime.now().isoformat()
            
            for endpoint, row in endpoint_stats.iterrows():
                # Skip endpoints with very few requests
                if row['count'] < 5:
                    continue
                    
                # Add overall response time metrics
                performance_metrics.append({
                    'timestamp': current_time,
                    'metric_name': 'mean_response_time',
                    'metric_value': row['mean_time'],
                    'endpoint': endpoint,
                    'time_window': 3600  # assume 1-hour window for this example
                })
                
                performance_metrics.append({
                    'timestamp': current_time,
                    'metric_name': 'p95_response_time',
                    'metric_value': row['p95_time'],
                    'endpoint': endpoint,
                    'time_window': 3600
                })
                
                # Add error rate metrics
                performance_metrics.append({
                    'timestamp': current_time,
                    'metric_name': 'error_rate',
                    'metric_value': row['error_rate'],
                    'endpoint': endpoint,
                    'time_window': 3600
                })
            
            return {
                'overall_stats': stats,
                'slow_endpoints': slow_endpoints.to_dict(),
                'performance_metrics': performance_metrics
            }
        else:
            logger.warning("No endpoint data available for detailed analysis")
            return {
                'overall_stats': stats,
                'slow_endpoints': {},
                'performance_metrics': []
            }
    
    def analyze_status_codes(self, logs_df):
        """
        Analyze HTTP status codes to identify error patterns.
        
        Args:
            logs_df (pandas.DataFrame): DataFrame containing parsed logs
            
        Returns:
            dict: Status code analysis and error patterns
        """
        if logs_df.empty or 'status' not in logs_df.columns:
            logger.warning("No status code data available for analysis")
            return {
                'status_counts': {},
                'error_rate': 0,
                'error_endpoints': {}
            }
        
        # Count status codes
        status_counts = logs_df['status'].value_counts().to_dict()
        
        # Calculate error rate
        total_requests = len(logs_df)
        error_count = sum(logs_df['status'] >= 400)
        error_rate = error_count / total_requests if total_requests > 0 else 0
        
        logger.info(f"Status code distribution: {status_counts}")
        logger.info(f"Overall error rate: {error_rate:.2%}")
        
        # Check if error rate exceeds threshold
        if error_rate > self.thresholds['high_error_rate']:
            logger.warning(f"High error rate detected: {error_rate:.2%}")
        
        # Analyze errors by endpoint if possible
        error_endpoints = {}
        if 'endpoint' in logs_df.columns:
            error_df = logs_df[logs_df['status'] >= 400]
            
            if not error_df.empty:
                error_by_endpoint = error_df.groupby('endpoint').size()
                total_by_endpoint = logs_df.groupby('endpoint').size()
                
                for endpoint in error_by_endpoint.index:
                    errors = error_by_endpoint[endpoint]
                    total = total_by_endpoint[endpoint]
                    error_endpoints[endpoint] = {
                        'error_count': int(errors),
                        'total_count': int(total),
                        'error_rate': float(errors / total)
                    }
        
        return {
            'status_counts': status_counts,
            'error_rate': error_rate,
            'error_endpoints': error_endpoints
        }
    
    def analyze_traffic_patterns(self, logs_df, time_interval='1H'):
        """
        Analyze traffic patterns over time.
        
        Args:
            logs_df (pandas.DataFrame): DataFrame containing parsed logs
            time_interval (str): Pandas time interval for resampling
            
        Returns:
            dict: Traffic patterns analysis
        """
        if logs_df.empty or 'timestamp' not in logs_df.columns:
            logger.warning("No timestamp data available for traffic analysis")
            return {
                'traffic_pattern': {},
                'peak_times': []
            }
        
        try:
            # Ensure timestamp is datetime
            if not pd.api.types.is_datetime64_any_dtype(logs_df['timestamp']):
                logs_df['timestamp'] = pd.to_datetime(logs_df['timestamp'], errors='coerce')
            
            # Set timestamp as index for time-based operations
            time_series = logs_df.set_index('timestamp')
            
            # Count requests per interval
            traffic = time_series.resample(time_interval).size()
            
            # Find peak traffic times (intervals with traffic above 95th percentile)
            threshold = traffic.quantile(0.95)
            peak_times = traffic[traffic > threshold]
            
            logger.info(f"Traffic pattern analyzed with interval {time_interval}")
            logger.info(f"Peak traffic threshold: {threshold} requests per interval")
            logger.info(f"Identified {len(peak_times)} peak traffic intervals")
            
            return {
                'traffic_pattern': traffic.to_dict(),
                'peak_times': peak_times.to_dict()
            }
            
        except Exception as e:
            logger.error(f"Error analyzing traffic patterns: {str(e)}")
            return {
                'traffic_pattern': {},
                'peak_times': []
            }
    
    def generate_performance_report(self, logs_df):
        """
        Generate a comprehensive performance report.
        
        Args:
            logs_df (pandas.DataFrame): DataFrame containing parsed logs
            
        Returns:
            dict: Complete performance report
        """
        logger.info("Generating comprehensive performance report")
        
        response_time_analysis = self.analyze_response_times(logs_df)
        status_code_analysis = self.analyze_status_codes(logs_df)
        
        try:
            traffic_analysis = self.analyze_traffic_patterns(logs_df)
        except Exception as e:
            logger.error(f"Error in traffic pattern analysis: {str(e)}")
            traffic_analysis = {'traffic_pattern': {}, 'peak_times': []}
        
        # Compile performance issues
        issues = []
        
        # Check for overall performance issues
        if (response_time_analysis['overall_stats'] and 
                response_time_analysis['overall_stats'].get('p95', 0) > 
                self.thresholds['slow_endpoint_p95']):
            issues.append({
                'type': 'high_overall_response_time',
                'severity': 'medium',
                'description': f"95th percentile response time "
                              f"({response_time_analysis['overall_stats']['p95']:.2f}s) "
                              f"exceeds threshold ({self.thresholds['slow_endpoint_p95']}s)",
                'metric': response_time_analysis['overall_stats']['p95']
            })
        
        # Check for high error rate
        if status_code_analysis['error_rate'] > self.thresholds['high_error_rate']:
            issues.append({
                'type': 'high_error_rate',
                'severity': 'high',
                'description': f"Error rate ({status_code_analysis['error_rate']:.2%}) "
                              f"exceeds threshold ({self.thresholds['high_error_rate']:.2%})",
                'metric': status_code_analysis['error_rate']
            })
        
        # Check for specific slow endpoints
        for endpoint, stats in response_time_analysis.get('slow_endpoints', {}).items():
            # Access nested dictionary values correctly
            if isinstance(stats, dict) and stats.get('mean_time', 0) > self.thresholds['slow_endpoint_avg']:
                issues.append({
                    'type': 'slow_endpoint',
                    'severity': 'medium',
                    'endpoint': endpoint,
                    'description': f"Endpoint {endpoint} has slow average response time "
                                  f"({stats['mean_time']:.2f}s)",
                    'metric': stats['mean_time']
                })
        
        return {
            'timestamp': datetime.now().isoformat(),
            'response_time_analysis': response_time_analysis,
            'status_code_analysis': status_code_analysis,
            'traffic_analysis': traffic_analysis,
            'issues_detected': issues,
            'performance_metrics': response_time_analysis.get('performance_metrics', [])
        }
