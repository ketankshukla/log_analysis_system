"""
Test script for the Log Analysis & Monitoring System.

This script runs a test analysis on sample log files to validate the system.
"""
import logging
import pandas as pd
import json
import os
from pathlib import Path

from src.utils.helpers import load_config, setup_logging
from src.parsers.apache_parser import ApacheLogParser
from src.analyzers.performance import PerformanceAnalyzer
from src.analyzers.security import SecurityAnalyzer
from src.alerting.detector import AnomalyDetector

# Setup logging
logger = setup_logging(log_level=logging.INFO)

def display_section(title):
    """Display a section header with proper formatting."""
    separator = "=" * 50
    print(f"\n{separator}")
    print(f"{title}")
    print(f"{separator}")

def main():
    """Run test analysis on sample log files."""
    logger.info("Starting test analysis")
    
    # Get the script's directory to make paths absolute
    script_dir = Path(os.path.dirname(os.path.abspath(__file__)))
    
    # Load configuration using absolute path
    config_path = script_dir / "config" / "config.yaml"
    try:
        config = load_config(str(config_path))
    except FileNotFoundError:
        logger.error(f"Configuration file not found at {config_path}")
        print(f"ERROR: Configuration file not found at {config_path}")
        print(f"Make sure you're running the script from the right location.")
        return
    
    # Initialize components
    parser = ApacheLogParser()
    perf_analyzer = PerformanceAnalyzer(config)
    security_analyzer = SecurityAnalyzer(config)
    anomaly_detector = AnomalyDetector(config)
    
    # Get sample log file with absolute path
    log_file = script_dir / "data" / "logs" / "sample_apache.log"
    
    if not log_file.exists():
        logger.error(f"Sample log file not found: {log_file}")
        print(f"ERROR: Sample log file not found at {log_file}")
        return
    
    logger.info(f"Using sample log file: {log_file}")
    
    # Parse logs
    parsed_logs = []
    with open(log_file, 'r', encoding='utf-8') as f:
        for line in f:
            parsed = parser.parse_line(line.strip())
            if parsed:
                parsed_logs.append(parsed)
    
    if not parsed_logs:
        logger.error("No logs were successfully parsed")
        print("ERROR: No logs were successfully parsed")
        return
    
    logger.info(f"Successfully parsed {len(parsed_logs)} log entries")
    
    # Convert to DataFrame
    logs_df = pd.DataFrame(parsed_logs)
    
    # Print sample of parsed data
    display_section("Sample of Parsed Log Data")
    try:
        print(logs_df[['timestamp', 'ip_address', 'method', 'endpoint', 'status', 'response_time']].head().to_string())
    except Exception as e:
        print(f"Error displaying DataFrame: {e}")
        print("Selected columns of sample data:")
        for i, row in logs_df.head().iterrows():
            print(f"Row {i}:")
            for col in ['timestamp', 'ip_address', 'method', 'endpoint', 'status', 'response_time']:
                if col in row:
                    print(f"  {col}: {row[col]}")
    
    # Run performance analysis
    display_section("Performance Analysis")
    perf_results = perf_analyzer.generate_performance_report(logs_df)
    
    print("Overall Stats:")
    for key, value in perf_results['response_time_analysis']['overall_stats'].items():
        print(f"  {key}: {value:.4f}")
    
    print("\nSlow Endpoints:")
    if perf_results['response_time_analysis']['slow_endpoints']:
        for endpoint, stats in perf_results['response_time_analysis']['slow_endpoints'].items():
            print(f"  {endpoint}: Avg: {stats.get('mean_time', 0):.4f}s, Max: {stats.get('max_time', 0):.4f}s")
    else:
        print("  None detected")
    
    print("\nStatus Code Distribution:")
    for status, count in perf_results['status_code_analysis']['status_counts'].items():
        print(f"  {status}: {count}")
    
    print(f"\nOverall Error Rate: {perf_results['status_code_analysis']['error_rate']:.2%}")
    
    # Run security analysis
    display_section("Security Analysis")
    security_results = security_analyzer.analyze_logs(logs_df)
    
    print(f"Potential Threats Detected: {security_results['potential_threats']}")
    
    if security_results['security_events']:
        print("\nSecurity Events:")
        for event in security_results['security_events']:
            print(f"  [{event['severity']}] {event['event_type']} - {event['description']}")
    else:
        print("\nNo security events detected")
    
    if security_results['ip_threat_scores']:
        print("\nIP Threat Scores:")
        for ip, data in security_results['ip_threat_scores'].items():
            print(f"  {ip}: Score: {data['score']}, Threat Level: {data['threat_level']}")
    else:
        print("\nNo IP threat scores calculated")
    
    # Run anomaly detection
    display_section("Anomaly Detection")
    anomaly_results = anomaly_detector.analyze_logs(logs_df)
    
    print(f"Anomalies Detected: {anomaly_results['anomalies_detected']}")
    
    if anomaly_results['anomaly_records']:
        print("\nAnomaly Records:")
        for record in anomaly_results['anomaly_records']:
            print(f"  {record['metric_name']}: Expected: {record['expected_value']:.4f}, "
                  f"Actual: {record['actual_value']:.4f}, Z-Score: {record['z_score']:.2f}")
    else:
        print("\nNo anomalies detected")
    
    logger.info("Test analysis completed")

if __name__ == "__main__":
    main()
