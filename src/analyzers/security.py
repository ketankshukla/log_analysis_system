"""
Security analyzer for the Log Analysis & Monitoring System.
"""
import re
import logging
import pandas as pd
from datetime import datetime
from collections import Counter

logger = logging.getLogger(__name__)

class SecurityAnalyzer:
    """
    Analyzes logs for security threats and suspicious activities.
    Identifies potential attacks, scanning attempts, and unauthorized access.
    """
    
    def __init__(self, config):
        """
        Initialize the security analyzer.
        
        Args:
            config (dict): Configuration dictionary containing security patterns
        """
        self.config = config
        self.attack_patterns = self._compile_patterns(config['security']['attack_patterns'])
        self.scan_patterns = self._compile_patterns(config['security']['scan_patterns'])
        self.suspicious_ips = self._load_suspicious_ips(config['security'].get('suspicious_ips_file'))
        
        logger.debug("Security analyzer initialized")
        
    def _compile_patterns(self, patterns):
        """
        Compile regex patterns for better performance.
        
        Args:
            patterns (list): List of regex pattern strings
            
        Returns:
            list: Compiled regex patterns
        """
        compiled = []
        for pattern in patterns:
            try:
                compiled.append(re.compile(pattern, re.IGNORECASE))
            except re.error as e:
                logger.error(f"Invalid regex pattern '{pattern}': {str(e)}")
        return compiled
    
    def _load_suspicious_ips(self, file_path):
        """
        Load list of known suspicious IPs from a file.
        
        Args:
            file_path (str): Path to file containing suspicious IPs
            
        Returns:
            set: Set of suspicious IP addresses
        """
        suspicious_ips = set()
        
        if not file_path:
            return suspicious_ips
            
        try:
            # Check if file exists before trying to open it
            import os
            if not os.path.exists(file_path):
                logger.warning(f"Suspicious IPs file not found: {file_path}")
                return suspicious_ips
                
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        suspicious_ips.add(line)
            
            logger.info(f"Loaded {len(suspicious_ips)} suspicious IPs from {file_path}")
        except Exception as e:
            logger.warning(f"Failed to load suspicious IPs from {file_path}: {str(e)}")
        
        return suspicious_ips
    
    def analyze_logs(self, logs_df):
        """
        Analyze logs for security threats.
        
        Args:
            logs_df (pandas.DataFrame): DataFrame containing parsed logs
            
        Returns:
            dict: Security analysis results
        """
        if logs_df.empty:
            logger.warning("No log data available for security analysis")
            return {
                'security_events': [],
                'ip_threat_scores': {},
                'potential_threats': 0
            }
        
        logger.info(f"Analyzing {len(logs_df)} log entries for security threats")
        
        # Detect potential attack patterns
        attack_events = self._detect_attack_patterns(logs_df)
        
        # Detect scanning attempts
        scan_events = self._detect_scanning_attempts(logs_df)
        
        # Detect suspicious IPs
        suspicious_ip_events = self._detect_suspicious_ips(logs_df)
        
        # Detect brute force attempts
        brute_force_events = self._detect_brute_force_attempts(logs_df)
        
        # Detect unusual HTTP methods
        unusual_method_events = self._detect_unusual_methods(logs_df)
        
        # Combine all security events
        all_security_events = (
            attack_events + 
            scan_events + 
            suspicious_ip_events + 
            brute_force_events +
            unusual_method_events
        )
        
        # Calculate threat scores for IPs
        ip_threat_scores = self._calculate_ip_threat_scores(all_security_events)
        
        logger.info(f"Detected {len(all_security_events)} potential security events")
        
        return {
            'security_events': all_security_events,
            'ip_threat_scores': ip_threat_scores,
            'potential_threats': len(all_security_events)
        }
    
    def _detect_attack_patterns(self, logs_df):
        """
        Detect potential attack patterns in request URLs.
        
        Args:
            logs_df (pandas.DataFrame): DataFrame containing parsed logs
            
        Returns:
            list: Security events for detected attacks
        """
        events = []
        current_time = datetime.now().isoformat()
        
        # Ensure we have the necessary columns
        if 'endpoint' not in logs_df.columns:
            return events
        
        # Check each endpoint for attack patterns
        for idx, row in logs_df.iterrows():
            endpoint = row['endpoint']
            ip_address = row.get('ip_address', 'unknown')
            
            for pattern in self.attack_patterns:
                if pattern.search(endpoint):
                    pattern_str = pattern.pattern
                    events.append({
                        'timestamp': row.get('timestamp', current_time),
                        'event_type': 'attack_pattern',
                        'severity': 'high',
                        'ip_address': ip_address,
                        'endpoint': endpoint,
                        'description': f"Potential attack pattern detected: {pattern_str}"
                    })
                    logger.warning(f"Attack pattern detected from {ip_address}: {pattern_str} in {endpoint}")
                    break  # Only report one pattern per request
        
        return events
    
    def _detect_scanning_attempts(self, logs_df):
        """
        Detect scanning attempts for sensitive files/directories.
        
        Args:
            logs_df (pandas.DataFrame): DataFrame containing parsed logs
            
        Returns:
            list: Security events for detected scanning attempts
        """
        events = []
        current_time = datetime.now().isoformat()
        
        # Ensure we have the necessary columns
        if 'endpoint' not in logs_df.columns:
            return events
        
        # Check each endpoint for scan patterns
        for idx, row in logs_df.iterrows():
            endpoint = row['endpoint']
            ip_address = row.get('ip_address', 'unknown')
            
            for pattern in self.scan_patterns:
                if pattern.search(endpoint):
                    pattern_str = pattern.pattern
                    events.append({
                        'timestamp': row.get('timestamp', current_time),
                        'event_type': 'scan_attempt',
                        'severity': 'medium',
                        'ip_address': ip_address,
                        'endpoint': endpoint,
                        'description': f"Potential scanning attempt detected: {pattern_str}"
                    })
                    logger.warning(f"Scan attempt detected from {ip_address}: {pattern_str} in {endpoint}")
                    break  # Only report one pattern per request
        
        return events
    
    def _detect_suspicious_ips(self, logs_df):
        """
        Detect activity from known suspicious IPs.
        
        Args:
            logs_df (pandas.DataFrame): DataFrame containing parsed logs
            
        Returns:
            list: Security events for suspicious IPs
        """
        events = []
        
        # Skip if we don't have suspicious IPs or IP address column
        if not self.suspicious_ips or 'ip_address' not in logs_df.columns:
            return events
        
        # Group by IP to avoid duplicate events
        ip_groups = logs_df.groupby('ip_address')
        
        for ip, group in ip_groups:
            if ip in self.suspicious_ips:
                first_row = group.iloc[0]
                events.append({
                    'timestamp': first_row.get('timestamp', datetime.now().isoformat()),
                    'event_type': 'suspicious_ip',
                    'severity': 'high',
                    'ip_address': ip,
                    'endpoint': first_row.get('endpoint', 'unknown'),
                    'description': f"Activity from known suspicious IP: {ip} ({len(group)} requests)"
                })
                logger.warning(f"Activity from known suspicious IP: {ip} ({len(group)} requests)")
        
        return events
    
    def _detect_brute_force_attempts(self, logs_df):
        """
        Detect potential brute force login attempts.
        
        Args:
            logs_df (pandas.DataFrame): DataFrame containing parsed logs
            
        Returns:
            list: Security events for brute force attempts
        """
        events = []
        
        # Skip if we don't have necessary columns
        if 'ip_address' not in logs_df.columns or 'endpoint' not in logs_df.columns or 'status' not in logs_df.columns:
            return events
        
        # Filter for login-related URLs and failed attempts
        login_keywords = ['login', 'signin', 'auth', 'wp-login', 'admin']
        login_attempts = logs_df[
            (logs_df['endpoint'].str.contains('|'.join(login_keywords), case=False, na=False)) &
            (logs_df['status'].isin([401, 403, 404]))
        ]
        
        if login_attempts.empty:
            return events
        
        # Count failed attempts by IP
        ip_counts = login_attempts.groupby('ip_address').size()
        
        # Report IPs with excessive failed attempts
        threshold = 5  # Consider configurable
        for ip, count in ip_counts.items():
            if count >= threshold:
                events.append({
                    'timestamp': datetime.now().isoformat(),
                    'event_type': 'brute_force_attempt',
                    'severity': 'high',
                    'ip_address': ip,
                    'endpoint': 'multiple',
                    'description': f"Potential brute force attempt: {count} failed login attempts from {ip}"
                })
                logger.warning(f"Potential brute force attempt: {count} failed login attempts from {ip}")
        
        return events
    
    def _detect_unusual_methods(self, logs_df):
        """
        Detect unusual HTTP methods.
        
        Args:
            logs_df (pandas.DataFrame): DataFrame containing parsed logs
            
        Returns:
            list: Security events for unusual HTTP methods
        """
        events = []
        
        # Skip if we don't have method column
        if 'method' not in logs_df.columns:
            return events
        
        # Define common and potentially dangerous methods
        common_methods = {'GET', 'POST', 'HEAD'}
        dangerous_methods = {'PUT', 'DELETE', 'TRACE', 'CONNECT', 'OPTIONS'}
        
        # Group by method and IP
        method_groups = logs_df.groupby(['method', 'ip_address'])
        
        for (method, ip), group in method_groups:
            if method not in common_methods and method in dangerous_methods:
                first_row = group.iloc[0]
                events.append({
                    'timestamp': first_row.get('timestamp', datetime.now().isoformat()),
                    'event_type': 'unusual_method',
                    'severity': 'medium',
                    'ip_address': ip,
                    'endpoint': first_row.get('endpoint', 'unknown'),
                    'description': f"Unusual HTTP method {method} used by {ip} ({len(group)} requests)"
                })
                logger.warning(f"Unusual HTTP method {method} used by {ip} ({len(group)} requests)")
        
        return events
    
    def _calculate_ip_threat_scores(self, security_events):
        """
        Calculate threat scores for IP addresses based on security events.
        
        Args:
            security_events (list): List of security events
            
        Returns:
            dict: IP addresses with threat scores
        """
        if not security_events:
            return {}
        
        # Define severity weights
        severity_weights = {
            'low': 1,
            'medium': 5,
            'high': 10
        }
        
        # Count events by IP address and calculate weighted scores
        ip_scores = {}
        
        for event in security_events:
            ip = event.get('ip_address')
            if not ip:
                continue
                
            severity = event.get('severity', 'medium')
            weight = severity_weights.get(severity, 1)
            
            if ip not in ip_scores:
                ip_scores[ip] = {
                    'score': 0,
                    'events': Counter()
                }
            
            ip_scores[ip]['score'] += weight
            ip_scores[ip]['events'][event.get('event_type', 'unknown')] += 1
        
        # Add human-readable threat level
        for ip, data in ip_scores.items():
            score = data['score']
            if score >= 20:
                data['threat_level'] = 'high'
            elif score >= 10:
                data['threat_level'] = 'medium'
            else:
                data['threat_level'] = 'low'
            
            # Convert Counter to regular dict for better serialization
            data['events'] = dict(data['events'])
        
        return ip_scores
