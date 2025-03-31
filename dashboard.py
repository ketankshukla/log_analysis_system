"""
Dashboard for the Log Analysis & Monitoring System.

This script provides a clean, formatted presentation of the log analysis results.
"""
import os
import sys
import logging
import argparse
import pandas as pd
from datetime import datetime
from pathlib import Path
from tabulate import tabulate

from src.utils.helpers import load_config, ensure_dir_exists
from src.parsers.apache_parser import ApacheLogParser
from src.analyzers.performance import PerformanceAnalyzer
from src.analyzers.security import SecurityAnalyzer
from src.alerting.detector import AnomalyDetector
from src.alerting.notifier import EmailNotifier

# Disable default logging to console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(f"logs/dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")]
)
logger = logging.getLogger(__name__)

def create_section(title, width=80):
    """Create a formatted section header."""
    print("\n" + "=" * width)
    print(f"{title.center(width)}")
    print("=" * width)

def format_table(data, headers=None, tablefmt="grid"):
    """Format data as a table."""
    try:
        if isinstance(data, pd.DataFrame):
            return tabulate(data, headers='keys', tablefmt=tablefmt, showindex=False)
        elif isinstance(data, list) and all(isinstance(item, dict) for item in data):
            return tabulate(data, headers='keys', tablefmt=tablefmt)
        elif isinstance(data, dict):
            # Convert dict to list of [key, value] pairs
            return tabulate([[k, v] for k, v in data.items()], 
                           headers=['Property', 'Value'], 
                           tablefmt=tablefmt)
        else:
            return str(data)
    except Exception as e:
        logger.error(f"Error formatting table: {e}")
        return str(data)

def analyze_logs(log_file, config):
    """Analyze log file and return results."""
    try:
        # Initialize components
        parser = ApacheLogParser()
        perf_analyzer = PerformanceAnalyzer(config)
        security_analyzer = SecurityAnalyzer(config)
        anomaly_detector = AnomalyDetector(config)
        
        # Parse logs
        parsed_logs = []
        print(f"Parsing log file: {log_file}...")
        with open(log_file, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                parsed = parser.parse_line(line.strip())
                if parsed:
                    parsed_logs.append(parsed)
                if (i+1) % 100 == 0:
                    print(f"Processed {i+1} lines...", end='\r')
        
        if not parsed_logs:
            print("No logs were successfully parsed!")
            return None
        
        print(f"\nSuccessfully parsed {len(parsed_logs)} log entries.")
        
        # Convert to DataFrame
        logs_df = pd.DataFrame(parsed_logs)
        
        # Run analyses
        results = {
            "parsed_data": logs_df,
            "performance": perf_analyzer.generate_performance_report(logs_df),
            "security": security_analyzer.analyze_logs(logs_df),
            "anomalies": anomaly_detector.analyze_logs(logs_df)
        }
        
        return results
    
    except Exception as e:
        logger.error(f"Error analyzing logs: {e}")
        print(f"Error analyzing logs: {e}")
        return None

def display_results(results):
    """Display formatted analysis results."""
    if not results:
        print("No results to display.")
        return
    
    # Sample of parsed data
    create_section("SAMPLE OF PARSED LOG DATA")
    columns_to_display = ['timestamp', 'ip_address', 'method', 'endpoint', 'status', 'response_time']
    sample_df = results["parsed_data"][columns_to_display].head(5)
    print(format_table(sample_df))
    
    # Performance analysis
    create_section("PERFORMANCE ANALYSIS")
    
    print("\nOverall Stats:")
    overall_stats = results["performance"]["response_time_analysis"]["overall_stats"]
    formatted_stats = {k: f"{v:.4f}" for k, v in overall_stats.items()}
    print(format_table(formatted_stats))
    
    print("\nSlow Endpoints:")
    slow_endpoints = results["performance"]["response_time_analysis"]["slow_endpoints"]
    if slow_endpoints:
        formatted_endpoints = []
        for endpoint, stats in slow_endpoints.items():
            formatted_endpoints.append({
                "Endpoint": endpoint,
                "Avg Time (s)": f"{stats.get('mean_time', 0):.4f}",
                "Max Time (s)": f"{stats.get('max_time', 0):.4f}",
                "Count": stats.get('count', 0)
            })
        print(format_table(formatted_endpoints))
    else:
        print("None detected")
    
    print("\nStatus Code Distribution:")
    status_counts = results["performance"]["status_code_analysis"]["status_counts"]
    formatted_status = []
    for status, count in status_counts.items():
        formatted_status.append({
            "Status Code": status,
            "Count": count,
            "Description": get_status_description(status)
        })
    print(format_table(formatted_status))
    
    error_rate = results["performance"]["status_code_analysis"]["error_rate"]
    print(f"\nOverall Error Rate: {error_rate:.2%}")
    
    # Security analysis
    create_section("SECURITY ANALYSIS")
    
    security = results["security"]
    print(f"Potential Threats Detected: {security['potential_threats']}")
    
    if security["security_events"]:
        print("\nSecurity Events:")
        formatted_events = []
        for event in security["security_events"]:
            formatted_events.append({
                "Severity": event["severity"],
                "Type": event["event_type"],
                "Description": event["description"],
                "IP": event.get("ip_address", "N/A"),
                "Timestamp": event.get("timestamp", "N/A")
            })
        print(format_table(formatted_events))
    else:
        print("\nNo security events detected")
    
    if security["ip_threat_scores"]:
        print("\nIP Threat Scores:")
        ip_scores = []
        for ip, data in security["ip_threat_scores"].items():
            ip_scores.append({
                "IP Address": ip,
                "Score": data["score"],
                "Threat Level": data["threat_level"],
                "Request Count": data.get("request_count", "N/A")
            })
        print(format_table(ip_scores))
    else:
        print("\nNo IP threat scores calculated")
    
    # Anomaly detection
    create_section("ANOMALY DETECTION")
    
    anomalies = results["anomalies"]
    print(f"Anomalies Detected: {anomalies['anomalies_detected']}")
    
    if anomalies["anomaly_records"]:
        print("\nAnomaly Records:")
        formatted_anomalies = []
        for record in anomalies["anomaly_records"]:
            formatted_anomalies.append({
                "Metric": record["metric_name"],
                "Expected": f"{record['expected_value']:.4f}",
                "Actual": f"{record['actual_value']:.4f}",
                "Z-Score": f"{record['z_score']:.2f}",
                "Timestamp": record.get("timestamp", "N/A")
            })
        print(format_table(formatted_anomalies))
    else:
        print("\nNo anomalies detected")

def get_status_description(status):
    """Get a description for HTTP status codes."""
    status_map = {
        200: "OK",
        201: "Created",
        204: "No Content",
        301: "Moved Permanently",
        302: "Found",
        304: "Not Modified",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
        504: "Gateway Timeout"
    }
    return status_map.get(status, "Unknown")

def main():
    """Run the dashboard application."""
    parser = argparse.ArgumentParser(description="Log Analysis Dashboard")
    parser.add_argument("--logfile", help="Path to log file to analyze", 
                        default="data/logs/sample_apache.log")
    parser.add_argument("--config", help="Path to configuration file",
                        default="config/config.yaml")
    args = parser.parse_args()
    
    # Load configuration
    try:
        config = load_config(args.config)
    except Exception as e:
        print(f"Error loading configuration: {e}")
        sys.exit(1)
    
    # Check if log file exists
    log_file = Path(args.logfile)
    if not log_file.exists():
        print(f"Log file not found: {log_file}")
        sys.exit(1)
    
    # Create header
    create_section("LOG ANALYSIS & MONITORING DASHBOARD")
    print(f"Analyzing file: {log_file}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Analyze logs
    results = analyze_logs(log_file, config)
    
    # Display results
    if results:
        display_results(results)
    
    create_section("ANALYSIS COMPLETE")

if __name__ == "__main__":
    main()
