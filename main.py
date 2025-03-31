"""
Log Analysis & Monitoring System - Main Application

This script serves as the entry point for the Log Analysis & Monitoring System.
It integrates the various components to process log files, analyze them for
performance issues and security threats, and generate alerts when necessary.
"""
import os
import sys
import logging
import argparse
from pathlib import Path
from datetime import datetime

import pandas as pd

from src.utils.helpers import load_config, ensure_dir_exists, get_log_files
from src.parsers.apache_parser import ApacheLogParser
from src.analyzers.performance import PerformanceAnalyzer
from src.analyzers.security import SecurityAnalyzer
from src.storage.database import LogDatabase
from src.alerting.detector import AnomalyDetector
from src.alerting.notifier import EmailNotifier

# Setup logging
def setup_logging(log_level=logging.INFO):
    """Configure logging for the application."""
    log_dir = Path('logs')
    ensure_dir_exists(log_dir)
    
    log_file = log_dir / f"app_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
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

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Log Analysis & Monitoring System'
    )
    
    parser.add_argument(
        '--config', 
        default='config/config.yaml',
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--log-dir',
        help='Directory containing log files to analyze (overrides config)'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='Set the logging level'
    )
    
    parser.add_argument(
        '--analyze-only',
        action='store_true',
        help='Analyze logs without storing results in database'
    )
    
    return parser.parse_args()

def main():
    """Main application entry point."""
    # Parse command line arguments
    args = parse_args()
    
    # Setup logging
    log_level = getattr(logging, args.log_level)
    logger = setup_logging(log_level)
    
    logger.info("Starting Log Analysis & Monitoring System")
    
    try:
        # Load configuration
        config = load_config(args.config)
        
        # Override log directory if specified
        if args.log_dir:
            config['logs']['source_dir'] = args.log_dir
        
        # Initialize components
        apache_parser = ApacheLogParser()
        db = None if args.analyze_only else LogDatabase(config['database']['path'])
        perf_analyzer = PerformanceAnalyzer(config)
        security_analyzer = SecurityAnalyzer(config)
        
        # Get log files to process
        log_dir = Path(config['logs']['source_dir'])
        logger.info(f"Looking for log files in {log_dir}")
        
        if not log_dir.exists():
            logger.error(f"Log directory {log_dir} does not exist")
            return 1
        
        log_files = get_log_files(log_dir)
        logger.info(f"Found {len(log_files)} log files to process")
        
        # Process each log file
        for log_file in log_files:
            logger.info(f"Processing {log_file}")
            
            # Detect log format
            log_format = apache_parser.detect_format(log_file)
            if log_format == 'unknown':
                logger.warning(f"Could not determine format of {log_file}, skipping")
                continue
            
            logger.info(f"Detected format: {log_format}")
            
            # Parse log file
            parsed_logs = []
            error_logs = []
            
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f):
                    try:
                        if log_format == 'error':
                            parsed = apache_parser.parse_line(line.strip(), log_type='error')
                            if parsed:
                                error_logs.append(parsed)
                        else:
                            parsed = apache_parser.parse_line(line.strip(), log_type='access')
                            if parsed:
                                parsed_logs.append(parsed)
                    except Exception as e:
                        logger.error(f"Error parsing line {i+1}: {str(e)}")
                        continue
            
            # Convert to DataFrames
            if parsed_logs:
                access_df = pd.DataFrame(parsed_logs)
                logger.info(f"Parsed {len(access_df)} access log entries")
                
                # Store in database if enabled
                if db:
                    db.store_access_logs(parsed_logs, source_file=log_file.name)
                
                # Analyze performance
                perf_results = perf_analyzer.generate_performance_report(access_df)
                logger.info(f"Performance analysis completed: {len(perf_results['issues_detected'])} issues detected")
                
                # Store performance metrics if enabled
                if db and perf_results['performance_metrics']:
                    db.store_performance_metrics(perf_results['performance_metrics'])
                
                # Analyze security
                security_results = security_analyzer.analyze_logs(access_df)
                logger.info(f"Security analysis completed: {security_results['potential_threats']} potential threats detected")
                
                # Store security events if enabled
                if db and security_results['security_events']:
                    db.store_security_events(security_results['security_events'])
            
            if error_logs:
                error_df = pd.DataFrame(error_logs)
                logger.info(f"Parsed {len(error_df)} error log entries")
                
                # Store in database if enabled
                if db:
                    db.store_error_logs(error_logs, source_file=log_file.name)
        
        # Clean up
        if db:
            db.close()
        
        logger.info("Log analysis completed successfully")
        return 0
        
    except Exception as e:
        logger.exception(f"An error occurred: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
