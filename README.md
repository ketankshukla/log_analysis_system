# Log Analysis & Monitoring System

## Project Overview
A Python-based system that processes server logs, extracts performance metrics, identifies security threats, and generates alerts for anomalies.

## Features
- Extract structured data from unstructured logs using regex pattern matching
- Identify performance bottlenecks and security threats
- Detect anomalies in server response times using statistical methods
- Send alerts for critical issues via email
- Archive processed logs automatically for storage optimization

## Tech Stack
- **Python**: Core programming language
- **regex**: Pattern matching for log parsing
- **Pandas**: Data analysis and manipulation
- **SQLite**: Local database for storing processed log data
- **smtplib**: Email notifications for alerts
- **logging**: System logging and monitoring

## Project Structure
```
log_analysis_system/
├── config/
│   ├── config.yaml        # Configuration settings
│   └── patterns.yaml      # Regex patterns for log parsing
├── data/
│   ├── logs/              # Source log files directory
│   └── database.db        # SQLite database for processed logs
├── logs/                  # Application logs directory
├── src/
│   ├── __init__.py
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── apache_parser.py  # Apache log parser
│   │   ├── nginx_parser.py   # Nginx log parser
│   │   └── custom_parser.py  # Custom log format parser
│   ├── analyzers/
│   │   ├── __init__.py
│   │   ├── performance.py    # Performance metrics analyzer
│   │   ├── security.py       # Security threat analyzer
│   │   └── error_analyzer.py # Error pattern analyzer
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── database.py       # Database operations
│   │   └── archiver.py       # Log archiving functionality
│   ├── alerting/
│   │   ├── __init__.py
│   │   ├── detector.py       # Anomaly detection logic
│   │   └── notifier.py       # Email notification system
│   └── utils/
│       ├── __init__.py
│       └── helpers.py        # Utility functions
├── tests/
│   ├── __init__.py
│   ├── test_parsers.py
│   ├── test_analyzers.py
│   └── test_alerting.py
├── main.py                # Entry point for the system
├── requirements.txt
└── .venv/                 # Virtual environment (not in version control)
```

## Setup Instructions

### 1. Environment Setup
The project uses a virtual environment to manage dependencies:

```powershell
# Navigate to project directory
cd log_analysis_system

# Activate virtual environment
.\.venv\Scripts\Activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration
Update the configuration files in the `config` directory:

- `config.yaml`: General settings, database paths, email configuration
- `patterns.yaml`: Regex patterns for different log formats

### 3. Database Initialization
The system will automatically create and initialize the SQLite database on first run.

## Implementation Guide

### Step 1: Log Parsing Module
Create parsers for different log formats that extract structured information using regex patterns.

**Example implementation of a basic log parser:**

```python
# src/parsers/apache_parser.py
import re
import yaml
from datetime import datetime
from ..utils.helpers import load_patterns

class ApacheLogParser:
    def __init__(self):
        # Load the apache patterns from configuration
        self.patterns = load_patterns()['apache']
        
    def parse_line(self, line):
        """
        Parse a single Apache log line and return structured data.
        """
        match = re.match(self.patterns['access_log'], line)
        if match:
            data = match.groupdict()
            # Convert timestamp to datetime object
            data['timestamp'] = datetime.strptime(
                data['timestamp'], 
                '%d/%b/%Y:%H:%M:%S %z'
            )
            # Convert response time to float
            data['response_time'] = float(data.get('response_time', 0))
            # Convert status code to integer
            data['status'] = int(data['status'])
            return data
        
        return None
```

### Step 2: Analysis Module
Create analyzers that process parsed logs to extract meaningful insights.

**Example implementation of performance analyzer:**

```python
# src/analyzers/performance.py
import pandas as pd
import numpy as np

class PerformanceAnalyzer:
    def __init__(self, config):
        self.config = config
        self.thresholds = config['performance_thresholds']
        
    def analyze_response_times(self, logs_df):
        """
        Analyze response times from parsed logs.
        Returns performance metrics and potential issues.
        """
        # Calculate basic statistics
        stats = {
            'mean': logs_df['response_time'].mean(),
            'median': logs_df['response_time'].median(),
            'p95': logs_df['response_time'].quantile(0.95),
            'p99': logs_df['response_time'].quantile(0.99),
            'max': logs_df['response_time'].max()
        }
        
        # Identify slow endpoints
        endpoint_stats = logs_df.groupby('endpoint').agg({
            'response_time': ['mean', 'median', 'count', 'max']
        })
        
        # Find endpoints exceeding thresholds
        slow_endpoints = endpoint_stats[
            endpoint_stats[('response_time', 'mean')] > 
            self.thresholds['slow_endpoint_avg']
        ]
        
        return {
            'overall_stats': stats,
            'slow_endpoints': slow_endpoints.to_dict()
        }
```

### Step 3: Storage Module
Create database handlers for storing and retrieving processed log data.

**Example implementation of database operations:**

```python
# src/storage/database.py
import sqlite3
import pandas as pd

class LogDatabase:
    def __init__(self, db_path):
        self.db_path = db_path
        self.conn = None
        self.initialize_db()
        
    def initialize_db(self):
        """Create database tables if they don't exist."""
        self.conn = sqlite3.connect(self.db_path)
        cursor = self.conn.cursor()
        
        # Create logs table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            ip_address TEXT,
            method TEXT,
            endpoint TEXT,
            protocol TEXT,
            status INTEGER,
            bytes_sent INTEGER,
            referer TEXT,
            user_agent TEXT,
            response_time REAL,
            log_type TEXT
        )
        ''')
        
        # Create index on timestamp for faster queries
        cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_timestamp ON logs(timestamp)
        ''')
        
        self.conn.commit()
        
    def store_logs(self, logs_data):
        """Store parsed logs in the database."""
        df = pd.DataFrame(logs_data)
        df.to_sql('logs', self.conn, if_exists='append', index=False)
        
    def get_logs_by_timeframe(self, start_time, end_time):
        """Retrieve logs within a specific timeframe."""
        query = """
        SELECT * FROM logs 
        WHERE timestamp BETWEEN ? AND ?
        """
        return pd.read_sql_query(
            query, 
            self.conn, 
            params=(start_time, end_time)
        )
        
    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()
```

### Step 4: Alerting System
Implement anomaly detection and notification mechanisms.

**Example implementation of anomaly detector:**

```python
# src/alerting/detector.py
import numpy as np
from scipy import stats

class AnomalyDetector:
    def __init__(self, config):
        self.config = config
        self.z_threshold = config['anomaly_detection']['z_score_threshold']
        
    def detect_response_time_anomalies(self, data):
        """
        Detect anomalies in response time data using z-score.
        Returns indices of anomalous data points.
        """
        if len(data) < 10:  # Need sufficient data for meaningful statistics
            return []
            
        z_scores = np.abs(stats.zscore(data))
        anomalies = np.where(z_scores > self.z_threshold)[0]
        
        return anomalies.tolist()
```

### Step 5: Main Application
Create the main entry point that integrates all components.

**Example implementation of main.py:**

```python
# main.py
import os
import yaml
import logging
import time
import pandas as pd
from pathlib import Path

from src.parsers.apache_parser import ApacheLogParser
from src.parsers.nginx_parser import NginxParser
from src.analyzers.performance import PerformanceAnalyzer
from src.analyzers.security import SecurityAnalyzer
from src.storage.database import LogDatabase
from src.alerting.detector import AnomalyDetector
from src.alerting.notifier import EmailNotifier

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_config():
    """Load configuration from YAML file."""
    with open('config/config.yaml', 'r') as f:
        return yaml.safe_load(f)

def main():
    logger.info("Starting Log Analysis & Monitoring System")
    
    # Load configuration
    config = load_config()
    
    # Initialize components
    apache_parser = ApacheLogParser()
    nginx_parser = NginxParser()
    db = LogDatabase(config['database']['path'])
    perf_analyzer = PerformanceAnalyzer(config)
    security_analyzer = SecurityAnalyzer(config)
    anomaly_detector = AnomalyDetector(config)
    email_notifier = EmailNotifier(config['email'])
    
    # Process log files
    log_dir = Path(config['logs']['source_dir'])
    for log_file in log_dir.glob('*.log'):
        logger.info(f"Processing log file: {log_file}")
        
        # Determine parser based on log file name
        if 'apache' in log_file.name.lower():
            parser = apache_parser
        elif 'nginx' in log_file.name.lower():
            parser = nginx_parser
        else:
            logger.warning(f"No suitable parser for {log_file.name}")
            continue
            
        # Parse log entries
        parsed_logs = []
        with open(log_file, 'r') as f:
            for line in f:
                parsed_line = parser.parse_line(line.strip())
                if parsed_line:
                    parsed_logs.append(parsed_line)
        
        if not parsed_logs:
            logger.warning(f"No valid log entries found in {log_file.name}")
            continue
            
        # Convert to DataFrame for analysis
        logs_df = pd.DataFrame(parsed_logs)
        
        # Store in database
        db.store_logs(parsed_logs)
        
        # Analyze performance
        perf_results = perf_analyzer.analyze_response_times(logs_df)
        
        # Analyze security
        security_results = security_analyzer.analyze_logs(logs_df)
        
        # Detect anomalies
        anomalies = anomaly_detector.detect_response_time_anomalies(
            logs_df['response_time'].values
        )
        
        # Generate alerts if necessary
        if len(anomalies) > 0:
            anomaly_data = logs_df.iloc[anomalies]
            logger.warning(f"Detected {len(anomalies)} anomalies")
            
            # Send email notification if threshold exceeded
            if len(anomalies) >= config['alerting']['min_anomalies_for_alert']:
                email_notifier.send_alert(
                    subject="Response Time Anomalies Detected",
                    content=f"Detected {len(anomalies)} anomalies in {log_file.name}",
                    data=anomaly_data
                )
    
    # Close database connection
    db.close()
    logger.info("Log analysis completed")

if __name__ == "__main__":
    main()
```

## Running the System

```powershell
# Activate virtual environment
.\.venv\Scripts\Activate

# Run the system
python main.py
```

## Testing

Run the tests using pytest:

```powershell
# Activate virtual environment
.\.venv\Scripts\Activate

# Run tests
pytest
```

## Next Steps

1. Implement additional log parsers for different formats
2. Add more sophisticated anomaly detection algorithms
3. Create a scheduled task to run the analysis automatically
4. Develop more comprehensive security threat detection
5. Implement log rotation and archiving for long-term storage
