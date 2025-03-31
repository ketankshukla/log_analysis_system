# Log Analysis & Monitoring System - User Guide

## Table of Contents
1. [Introduction](#introduction)
2. [System Requirements](#system-requirements)
3. [Setup Instructions](#setup-instructions)
4. [Usage Guide](#usage-guide)
   - [Using Sample Data](#using-sample-data)
   - [Using Your Own Log Files](#using-your-own-log-files)
   - [Running the Dashboard](#running-the-dashboard)
   - [Running the Main Application](#running-the-main-application)
5. [Understanding the Output](#understanding-the-output)
6. [Troubleshooting](#troubleshooting)

## Introduction

The Log Analysis & Monitoring System is a Python-based tool designed to process server log files, analyze them for performance issues, security threats, and anomalous patterns. The system works with log files you already have - **you do not need to have Apache or any web server installed locally** to use this tool.

Instead, you can:
- Use the included sample Apache log file
- Analyze log files from your production or test servers
- Process historical log data you've archived

## System Requirements

- Windows 11 with PowerShell
- Python 3.9 or higher
- The dependencies listed in `requirements.txt`

## Setup Instructions

1. **Activate the virtual environment**:
   ```powershell
   # From the project root directory
   .\.venv\Scripts\Activate.ps1
   ```
   You should see `(.venv)` prefix in your PowerShell prompt.

2. **Ensure all dependencies are installed**:
   ```powershell
   pip install -r requirements.txt
   ```

## Usage Guide

### Using Sample Data

The system comes with a sample Apache log file located at `data/logs/sample_apache.log`. You don't need Apache installed to use this file, as it's a static text file containing log entries in the Apache format.

### Using Your Own Log Files

You can analyze your own log files by placing them in the `data/logs` directory or specifying the full path when running the tool.

Log files should be in one of the supported formats:
- Apache access logs
- Apache error logs
- Nginx logs (if implemented)

### Running the Dashboard

The dashboard provides a visually formatted view of the analysis results:

1. Ensure your virtual environment is activated
2. Run the dashboard with the sample log:
   ```powershell
   python dashboard.py
   ```

3. To analyze a specific log file:
   ```powershell
   python dashboard.py --logfile "path\to\your\logfile.log"
   ```

### Running the Main Application

The main application performs a full analysis and can store results in a database:

1. Ensure your virtual environment is activated
2. Run the main application:
   ```powershell
   python main.py
   ```

3. To run with specific parameters:
   ```powershell
   python main.py --input "path\to\logs" --config "path\to\config.yaml"
   ```

## Understanding the Output

The analysis results include several key sections:

1. **Parsed Log Data**: A sample of the parsed log entries showing how the system interpreted the raw logs.

2. **Performance Analysis**:
   - Overall response time statistics
   - Identification of slow endpoints
   - Status code distribution
   - Error rates

3. **Security Analysis**:
   - Potential security threats detected
   - Suspicious IP addresses
   - Possible attack patterns

4. **Anomaly Detection**:
   - Statistical outliers in response times
   - Unusual traffic patterns
   - Unexpected error rates

## Troubleshooting

### Common Issues

1. **"No module named 'X'"**:
   - Ensure your virtual environment is activated
   - Run `pip install -r requirements.txt` to install all dependencies

2. **"No logs were successfully parsed"**:
   - Verify your log file format matches the expected format
   - Check if the log file is accessible and not empty

3. **Display formatting issues**:
   - Ensure the terminal window is wide enough to display tables
   - Try running the script with the `--simple-output` flag (if implemented)

4. **"File not found" errors**:
   - Use full paths when specifying files outside the project directory
   - Verify directory structure matches what's expected in the config

### Getting Help

If you encounter issues not covered in this guide:

1. Check the system logs in the `logs/` directory
2. Review the configuration in `config/config.yaml`
3. Refer to the project README.md for additional documentation
