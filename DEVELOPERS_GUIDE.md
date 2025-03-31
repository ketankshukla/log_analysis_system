# Log Analysis & Monitoring System - Developer's Guide

## Table of Contents
1. [System Architecture](#system-architecture)
2. [Entry Points](#entry-points)
   - [main.py](#mainpy)
   - [test_analysis.py](#test_analysispy)
   - [dashboard.py](#dashboardpy)
3. [Core Modules](#core-modules)
   - [Parsers](#parsers)
   - [Analyzers](#analyzers)
   - [Alerting](#alerting)
   - [Storage](#storage)
   - [Utils](#utils)
4. [Data Flow](#data-flow)
5. [Configuration System](#configuration-system)
6. [Extending the System](#extending-the-system)
7. [Testing](#testing)
8. [Performance Considerations](#performance-considerations)

## System Architecture

The Log Analysis & Monitoring System is built with a modular architecture that separates concerns into distinct components:

```
log_analysis_system/
│
├── config/                 # Configuration files
│   ├── config.yaml         # Main configuration
│   ├── patterns.yaml       # Regex patterns for log parsing
│   └── suspicious_ips.txt  # Known malicious IP addresses
│
├── data/                   # Data storage
│   └── logs/               # Log files to analyze
│       └── sample_apache.log  # Sample file for testing
│
├── logs/                   # Application logs
│
├── src/                    # Source code
│   ├── alerting/           # Alerting and anomaly detection
│   │   └── detector.py     # Anomaly detection algorithms
│   │
│   ├── analyzers/          # Log analysis modules
│   │   ├── performance.py  # Performance analysis
│   │   └── security.py     # Security threat detection
│   │
│   ├── parsers/            # Log parsing modules
│   │   └── apache_parser.py # Parser for Apache logs
│   │
│   ├── storage/            # Data persistence
│   │   └── database.py     # Database operations
│   │
│   └── utils/              # Utility functions
│       └── helpers.py      # Helper utilities
│
├── main.py                 # Main entry point
├── dashboard.py            # Interactive dashboard
├── test_analysis.py        # Test script for quick analysis
└── requirements.txt        # Python dependencies
```

This architecture provides:
- Clear separation of concerns
- Modular components that can be independently tested
- Easy extension points for adding new functionality
- Configurable behavior through external configuration files

## Entry Points

### main.py

`main.py` is the primary entry point of the application intended for production use. When executed, it:

1. **Initializes the system**:
   - Sets up logging
   - Loads configuration
   - Connects to storage (if configured)

2. **Processes log files**:
   - Discovers log files based on configuration
   - For each log file:
     - Selects appropriate parser based on file type
     - Parses log entries
     - Passes parsed data to analyzers

3. **Runs analysis modules**:
   - Performance analysis (response times, error rates, etc.)
   - Security analysis (threat detection, suspicious activity)
   - Anomaly detection (statistical outliers)

4. **Generates alerts**:
   - Evaluates alert conditions from analyzer results
   - Sends notifications based on severity and configuration
   - Records alert history

5. **Stores results**:
   - Persists analysis results to database
   - Maintains historical data for trend analysis

6. **Cleanup**:
   - Closes connections
   - Generates summary report

Example execution workflow:
```
1. Load configuration from config/config.yaml
2. Initialize database connection
3. Discover log files in data/logs/
4. For each log file:
   a. Determine log type (Apache, Nginx, etc.)
   b. Parse log entries into structured data
   c. Run performance and security analyzers
   d. Check for anomalies
   e. Generate alerts for detected issues
   f. Store results in database
5. Generate summary report
6. Close database connection
```

### test_analysis.py

`test_analysis.py` is a simplified version of the main application designed for quick testing and demonstration. It:

1. **Initializes minimal components**:
   - Sets up basic logging
   - Loads configuration
   - Creates in-memory structures instead of persistent storage

2. **Processes a sample log file**:
   - Uses the sample_apache.log file in data/logs/
   - Parses entries using the Apache log parser
   - Displays a sample of parsed entries

3. **Runs analysis with visual output**:
   - Performance analysis with key metrics
   - Security analysis with threat detection
   - Basic anomaly detection

4. **Displays results to console**:
   - Formatted tables of analysis results
   - Summary statistics
   - Detected threats and anomalies

Example execution workflow:
```
1. Load configuration from config/config.yaml
2. Initialize analyzer components
3. Load sample log file (data/logs/sample_apache.log)
4. Parse log entries
5. Display sample of parsed data
6. Run performance analyzer and display results
7. Run security analyzer and display results
8. Run anomaly detector and display results
9. Output summary
```

The key difference between `main.py` and `test_analysis.py` is that:
- `main.py` is designed for production use with full functionality
- `test_analysis.py` is for quick testing/demonstration with visual output
- `main.py` uses persistent storage, while `test_analysis.py` is in-memory
- `main.py` can process multiple log files, while `test_analysis.py` focuses on a sample

### dashboard.py

`dashboard.py` provides a formatted, console-based dashboard for visualizing log analysis results:

1. **Initializes the visualization components**:
   - Sets up logging
   - Loads configuration
   - Configures display formatting

2. **Processes specified log file**:
   - Accepts command line arguments for log file path
   - Defaults to sample log if no path provided
   - Parses log entries using appropriate parser

3. **Runs analysis modules with visual output**:
   - Performance analysis with tables and statistics
   - Security analysis with threat detection and scoring
   - Anomaly detection with highlighted outliers

4. **Displays dashboard in console**:
   - Formatted tables using tabulate
   - Clear section headers
   - Summary statistics
   - Timestamp for the analysis run

The dashboard is ideal for regular monitoring and quick analysis reviews.

## Core Modules

### Parsers

The parsing modules convert raw log text into structured data:

**ApacheLogParser** (`src/parsers/apache_parser.py`):
- Parses Apache common log format
- Parses Apache combined log format
- Extracts fields like IP address, timestamp, HTTP method, endpoint, status code, etc.
- Uses regex patterns from `config/patterns.yaml` for flexibility

The parser workflow:
1. Load regex patterns from configuration
2. For each log line:
   - Apply appropriate regex pattern based on log format
   - Extract fields into a structured dictionary
   - Convert data types (e.g., timestamps, integers)
   - Return parsed entry or None if parsing fails
3. Aggregate parsed entries into a collection

To add a new parser:
1. Create a new file in `src/parsers/`
2. Implement similar interface as existing parsers
3. Add appropriate regex patterns to `config/patterns.yaml`
4. Update factory method to return new parser based on log type

### Analyzers

Analyzers process parsed log data to extract insights:

**PerformanceAnalyzer** (`src/analyzers/performance.py`):
- Calculates response time statistics (mean, median, percentiles)
- Identifies slow endpoints
- Monitors error rates and status code distribution
- Analyzes traffic patterns over time
- Detects performance bottlenecks

The performance analyzer workflow:
1. Receive parsed log entries
2. Group and aggregate data (by endpoint, timestamp, etc.)
3. Calculate statistics (mean, median, percentiles)
4. Identify outliers and bottlenecks
5. Generate performance report

**SecurityAnalyzer** (`src/analyzers/security.py`):
- Detects potential security threats
- Identifies suspicious IPs using patterns and known-bad list
- Recognizes attack patterns (SQL injection, path traversal, etc.)
- Scores IP addresses based on suspicious activity
- Tracks failed login attempts and brute force attacks

The security analyzer workflow:
1. Load suspicious IPs from configuration
2. Receive parsed log entries
3. Apply detection rules to each entry
4. Score and classify detected threats
5. Aggregate threat data by IP, attack type, etc.
6. Generate security report

### Alerting

The alerting module detects anomalies and generates notifications:

**AnomalyDetector** (`src/alerting/detector.py`):
- Implements statistical methods for anomaly detection (z-score, IQR, etc.)
- Analyzes time series data for unusual patterns
- Detects sudden changes in metrics (error rates, response times, etc.)
- Sets thresholds based on historical data
- Generates alerts for abnormal conditions

The anomaly detection workflow:
1. Receive metrics from analyzers
2. Apply statistical methods to detect outliers
3. Compare current values against historical baselines
4. Generate alerts for significant deviations
5. Track alert history and status

### Storage

The storage module handles data persistence:

**Database** (`src/storage/database.py`):
- Provides interface to database system
- Stores analysis results for historical trending
- Maintains alert history
- Supports queries for dashboard and reporting
- Handles data retention policies

The database workflow:
1. Initialize connection based on configuration
2. Create schema if needed
3. Store parsed log entries
4. Store analysis results
5. Retrieve data for dashboards and reports
6. Implement data retention policies

### Utils

Utility modules provide common functionality:

**Helpers** (`src/utils/helpers.py`):
- Configuration loading and management
- Logging setup and configuration
- Path resolution and file handling
- Common utility functions
- Timestamp formatting and manipulation

## Data Flow

The data flows through the system in the following sequence:

1. **Log Discovery**:
   - Log files are located in the configured directories
   - File types are determined based on naming conventions or content

2. **Parsing**:
   - Raw log text is converted to structured data
   - Data types are normalized
   - Timestamps are standardized
   - Invalid entries are filtered out

3. **Analysis**:
   - Structured data is passed to analyzers
   - Each analyzer processes the data for its domain (performance, security)
   - Analysis results are generated
   - Metrics are calculated

4. **Anomaly Detection**:
   - Metrics from analyzers are evaluated for anomalies
   - Statistical methods are applied
   - Thresholds are calculated
   - Anomalies are identified

5. **Alerting**:
   - Anomalies trigger alerts
   - Alerts are classified by severity
   - Notifications are generated
   - Alert status is tracked

6. **Storage**:
   - Parsed data is stored (if configured)
   - Analysis results are persisted
   - Alert history is maintained
   - Historical data is managed

7. **Reporting**:
   - Analysis results are formatted for display
   - Dashboards are updated
   - Reports are generated
   - Visualizations are created

## Configuration System

The configuration system uses YAML files for flexibility:

**Main Configuration** (`config/config.yaml`):
- Log file locations and types
- Analysis parameters and thresholds
- Database connection settings
- Alerting rules and notification methods
- System-wide settings

**Pattern Configuration** (`config/patterns.yaml`):
- Regular expression patterns for log parsing
- Patterns for different log formats
- Custom patterns for application-specific logs

**Suspicious IPs** (`config/suspicious_ips.txt`):
- List of known malicious IP addresses
- Comments for describing threat sources
- Optional score or category

Configuration is loaded at startup and can be reloaded at runtime for dynamic configuration changes.

## Extending the System

The system is designed for easy extension:

**Adding a New Parser**:
1. Create a new file in `src/parsers/`
2. Implement the parser interface
3. Add patterns to `config/patterns.yaml`
4. Update factory method in main module

**Adding a New Analyzer**:
1. Create a new file in `src/analyzers/`
2. Implement the analyzer interface
3. Update configuration as needed
4. Integrate with main workflow

**Adding a New Alert Type**:
1. Extend the detector in `src/alerting/detector.py`
2. Implement the new detection algorithm
3. Add configuration parameters
4. Update alerting workflow

**Adding a New Storage Backend**:
1. Create a new implementation in `src/storage/`
2. Implement the storage interface
3. Add connection parameters to configuration
4. Update the storage factory method

## Testing

The system includes several testing strategies:

**Unit Tests**:
- Test individual components in isolation
- Mock dependencies
- Focus on algorithm correctness

**Integration Tests**:
- Test component interactions
- Use test fixtures for sample data
- Verify data flow between modules

**End-to-End Tests**:
- Test complete system
- Use sample log files
- Verify expected outputs

**Performance Tests**:
- Test system under load
- Measure resource usage
- Verify scalability

## Performance Considerations

The system is designed with performance in mind:

**Efficient Parsing**:
- Compiled regex patterns for speed
- Streaming processing for large files
- Lazy evaluation where appropriate

**Optimized Analysis**:
- Vectorized operations with pandas
- Incremental processing for large datasets
- Caching of intermediate results

**Storage Efficiency**:
- Selective storage of relevant data
- Data aggregation for historical storage
- Index optimization for query performance

**Resource Management**:
- Configurable batch sizes
- Memory usage limits
- Background processing for heavy operations

For extremely large log files, consider:
- Implementing sharding for parallel processing
- Using distributed processing frameworks
- Implementing stream processing for real-time analysis
