"""
Apache log parser for the Log Analysis & Monitoring System.
"""
import re
import logging
from datetime import datetime
from ..utils.helpers import load_patterns

logger = logging.getLogger(__name__)

class ApacheLogParser:
    """
    Parser for Apache HTTP Server log files.
    Supports Common Log Format (CLF), Combined Log Format, and custom formats with response time.
    """
    
    def __init__(self):
        """Initialize the Apache log parser with regex patterns from configuration."""
        self.patterns = load_patterns()['apache']
        
        # Compile regex patterns for better performance
        self.compiled_patterns = {
            'common': re.compile(self.patterns['common_log']),
            'combined': re.compile(self.patterns['combined_log']),
            'combined_time': re.compile(self.patterns['combined_with_time']),
            'error': re.compile(self.patterns['error_log'])
        }
        
        logger.debug("Apache log parser initialized")
    
    def parse_line(self, line, log_type='access'):
        """
        Parse a single line from an Apache log file.
        
        Args:
            line (str): The log line to parse
            log_type (str): Type of log - 'access' or 'error'
            
        Returns:
            dict: Parsed log entry or None if parsing failed
        """
        if not line or not line.strip():
            return None
            
        try:
            if log_type == 'error':
                return self._parse_error_log(line)
            else:
                return self._parse_access_log(line)
        except Exception as e:
            logger.error(f"Error parsing Apache log line: {str(e)}")
            logger.debug(f"Problematic line: {line}")
            return None
    
    def _parse_access_log(self, line):
        """Parse an Apache access log line."""
        # Try all access log formats, from most specific to least specific
        for format_name, pattern in [
            ('combined_time', self.compiled_patterns['combined_time']),
            ('combined', self.compiled_patterns['combined']),
            ('common', self.compiled_patterns['common'])
        ]:
            match = pattern.match(line)
            if match:
                data = match.groupdict()
                
                # Convert timestamp
                try:
                    # Common Apache timestamp format: 10/Oct/2023:13:55:36 -0700
                    data['timestamp'] = datetime.strptime(
                        data['timestamp'].split()[0],  # Remove timezone
                        '%d/%b/%Y:%H:%M:%S'
                    )
                except ValueError:
                    logger.warning(f"Failed to parse timestamp: {data.get('timestamp')}")
                    data['timestamp'] = None
                
                # Convert numeric fields
                try:
                    data['status'] = int(data['status'])
                except (ValueError, TypeError):
                    data['status'] = 0
                    
                try:
                    if data['bytes_sent'] == '-':
                        data['bytes_sent'] = 0
                    else:
                        data['bytes_sent'] = int(data['bytes_sent'])
                except (ValueError, TypeError):
                    data['bytes_sent'] = 0
                
                # Convert response time if present
                if 'response_time' in data:
                    try:
                        data['response_time'] = float(data['response_time'])
                    except (ValueError, TypeError):
                        data['response_time'] = 0.0
                else:
                    data['response_time'] = 0.0
                
                # Add metadata
                data['log_format'] = format_name
                data['log_type'] = 'access'
                
                return data
        
        # If we get here, no pattern matched
        logger.warning(f"Could not parse Apache access log line: {line[:50]}...")
        return None
    
    def _parse_error_log(self, line):
        """Parse an Apache error log line."""
        match = self.compiled_patterns['error'].match(line)
        if match:
            data = match.groupdict()
            
            # Convert timestamp
            try:
                # Error log timestamp format: Wed Oct 11 14:32:52 2023
                data['timestamp'] = datetime.strptime(
                    data['timestamp'],
                    '%a %b %d %H:%M:%S %Y'
                )
            except ValueError:
                logger.warning(f"Failed to parse error timestamp: {data.get('timestamp')}")
                data['timestamp'] = None
            
            # Add metadata
            data['log_type'] = 'error'
            
            return data
        
        logger.warning(f"Could not parse Apache error log line: {line[:50]}...")
        return None
        
    def detect_format(self, log_file_path):
        """
        Detect the format of an Apache log file by sampling lines.
        
        Args:
            log_file_path (str): Path to log file
            
        Returns:
            str: Detected format ('common', 'combined', 'combined_time', 'error', or 'unknown')
        """
        format_counts = {'common': 0, 'combined': 0, 'combined_time': 0, 'error': 0}
        total_lines = 0
        
        try:
            with open(log_file_path, 'r') as f:
                # Sample up to 100 lines
                for _ in range(100):
                    line = f.readline()
                    if not line:
                        break
                        
                    total_lines += 1
                    
                    # Check if this is an error log
                    if self.compiled_patterns['error'].match(line):
                        format_counts['error'] += 1
                        continue
                    
                    # Check access log formats
                    if self.compiled_patterns['combined_time'].match(line):
                        format_counts['combined_time'] += 1
                    elif self.compiled_patterns['combined'].match(line):
                        format_counts['combined'] += 1
                    elif self.compiled_patterns['common'].match(line):
                        format_counts['common'] += 1
        
        except Exception as e:
            logger.error(f"Error detecting log format for {log_file_path}: {str(e)}")
            return 'unknown'
            
        if total_lines == 0:
            return 'unknown'
            
        # Find the format with the highest match count
        best_format = max(format_counts.items(), key=lambda x: x[1])
        
        # If we have a clear winner
        if best_format[1] > 0 and best_format[1] / total_lines >= 0.5:
            return best_format[0]
            
        return 'unknown'
