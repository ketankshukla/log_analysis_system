"""
Email notification system for the Log Analysis & Monitoring System.

This module provides functionality for sending email alerts when
anomalies or security threats are detected in the logs.
"""
import os
import logging
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta

import pandas as pd

logger = logging.getLogger(__name__)

class EmailNotifier:
    """
    Sends email notifications for alerts and anomalies.
    """
    
    def __init__(self, config):
        """
        Initialize the email notifier.
        
        Args:
            config (dict): Email configuration settings
        """
        self.config = config
        self.enabled = config.get('enabled', False)
        self.smtp_server = config.get('smtp_server', '')
        self.smtp_port = config.get('smtp_port', 587)
        self.use_tls = config.get('use_tls', True)
        self.username = config.get('username', '')
        self.password = config.get('password', '')
        self.from_address = config.get('from_address', '')
        self.to_addresses = config.get('to_addresses', [])
        
        # Throttling configuration
        self.last_notification_time = {}  # Dict to track last notification for each alert type
        self.throttle_period = config.get('throttle_period', 3600)  # seconds
        
        if self.enabled:
            logger.info("Email notification system initialized")
        else:
            logger.info("Email notification system disabled")
    
    def _should_throttle(self, alert_type):
        """
        Check if notification should be throttled.
        
        Args:
            alert_type (str): Type of alert
            
        Returns:
            bool: True if notification should be throttled
        """
        current_time = datetime.now()
        
        # If we haven't seen this alert type before, don't throttle
        if alert_type not in self.last_notification_time:
            self.last_notification_time[alert_type] = current_time
            return False
        
        # Check if enough time has elapsed since the last notification
        last_time = self.last_notification_time[alert_type]
        elapsed = (current_time - last_time).total_seconds()
        
        if elapsed < self.throttle_period:
            logger.info(f"Throttling {alert_type} notification (last sent {elapsed:.0f}s ago)")
            return True
        
        # Update the last notification time
        self.last_notification_time[alert_type] = current_time
        return False
    
    def send_alert(self, subject, content, data=None, alert_type='general'):
        """
        Send an email alert.
        
        Args:
            subject (str): Email subject
            content (str): Email content
            data (pandas.DataFrame or dict, optional): Data to include in the email
            alert_type (str): Type of alert for throttling purposes
            
        Returns:
            bool: True if email was sent successfully
        """
        if not self.enabled:
            logger.info("Email notifications are disabled, alert not sent")
            return False
        
        # Check for throttling
        if self._should_throttle(alert_type):
            return False
        
        # Validate configuration
        if not self.smtp_server or not self.from_address or not self.to_addresses:
            logger.error("Email configuration incomplete, cannot send alert")
            return False
        
        try:
            # Create message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[Log Analysis Alert] {subject}"
            msg["From"] = self.from_address
            msg["To"] = ", ".join(self.to_addresses)
            
            # Create the text part of the email
            text_content = f"{content}\n\n"
            text_content += f"Alert Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            
            # Add data if provided
            if data is not None:
                text_content += "\nAlert Details:\n"
                
                if isinstance(data, pd.DataFrame):
                    # Format DataFrame as text table
                    text_content += "\n" + data.to_string() + "\n"
                elif isinstance(data, dict):
                    # Format dictionary
                    for key, value in data.items():
                        text_content += f"{key}: {value}\n"
                else:
                    # Just convert to string
                    text_content += str(data) + "\n"
            
            # Create the HTML part with better formatting
            html_content = f"""
            <html>
              <head>
                <style>
                  body {{ font-family: Arial, sans-serif; }}
                  .header {{ background-color: #f0f0f0; padding: 10px; }}
                  .content {{ padding: 15px; }}
                  table {{ border-collapse: collapse; width: 100%; }}
                  th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                  th {{ background-color: #f2f2f2; }}
                  tr:nth-child(even) {{ background-color: #f9f9f9; }}
                </style>
              </head>
              <body>
                <div class="header">
                  <h2>{subject}</h2>
                  <p>Alert Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                <div class="content">
                  <p>{content}</p>
            """
            
            # Add data if provided
            if data is not None:
                html_content += "<h3>Alert Details:</h3>"
                
                if isinstance(data, pd.DataFrame):
                    # Format DataFrame as HTML table
                    html_content += data.to_html(index=True)
                elif isinstance(data, dict):
                    # Format dictionary as HTML table
                    html_content += "<table>"
                    html_content += "<tr><th>Key</th><th>Value</th></tr>"
                    for key, value in data.items():
                        html_content += f"<tr><td>{key}</td><td>{value}</td></tr>"
                    html_content += "</table>"
                else:
                    # Just convert to string
                    html_content += f"<pre>{str(data)}</pre>"
            
            # Close HTML tags
            html_content += """
                </div>
              </body>
            </html>
            """
            
            # Attach parts to the message
            part1 = MIMEText(text_content, "plain")
            part2 = MIMEText(html_content, "html")
            msg.attach(part1)
            msg.attach(part2)
            
            # Send the message
            context = ssl.create_default_context() if self.use_tls else None
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls(context=context)
                
                if self.username and self.password:
                    server.login(self.username, self.password)
                
                server.sendmail(
                    self.from_address,
                    self.to_addresses,
                    msg.as_string()
                )
            
            logger.info(f"Alert email sent to {', '.join(self.to_addresses)}: {subject}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending email alert: {str(e)}")
            return False
    
    def send_performance_alert(self, perf_issues, timestamp=None):
        """
        Send an alert about performance issues.
        
        Args:
            perf_issues (list): List of performance issues
            timestamp (str, optional): Timestamp for the alert
            
        Returns:
            bool: True if email was sent successfully
        """
        if not perf_issues:
            return False
        
        num_issues = len(perf_issues)
        subject = f"Performance Issues Detected: {num_issues} issue(s)"
        
        content = "The following performance issues were detected in the log analysis:\n\n"
        
        # Create a DataFrame for better formatting
        issues_df = pd.DataFrame(perf_issues)
        
        return self.send_alert(subject, content, issues_df, alert_type='performance')
    
    def send_security_alert(self, security_events, timestamp=None):
        """
        Send an alert about security threats.
        
        Args:
            security_events (list): List of security events
            timestamp (str, optional): Timestamp for the alert
            
        Returns:
            bool: True if email was sent successfully
        """
        if not security_events:
            return False
        
        num_events = len(security_events)
        subject = f"Security Threats Detected: {num_events} event(s)"
        
        content = "The following security threats were detected in the log analysis:\n\n"
        
        # Create a DataFrame for better formatting
        events_df = pd.DataFrame(security_events)
        
        return self.send_alert(subject, content, events_df, alert_type='security')
    
    def send_anomaly_alert(self, anomalies, timestamp=None):
        """
        Send an alert about detected anomalies.
        
        Args:
            anomalies (list): List of anomalies
            timestamp (str, optional): Timestamp for the alert
            
        Returns:
            bool: True if email was sent successfully
        """
        if not anomalies:
            return False
        
        num_anomalies = len(anomalies)
        subject = f"Anomalies Detected: {num_anomalies} anomaly(ies)"
        
        content = "The following anomalies were detected in the log analysis:\n\n"
        
        # Create a DataFrame for better formatting
        anomalies_df = pd.DataFrame(anomalies)
        
        return self.send_alert(subject, content, anomalies_df, alert_type='anomaly')
    
    def send_daily_summary(self, stats, issues, timeframe):
        """
        Send a daily summary of log analysis.
        
        Args:
            stats (dict): Dictionary of statistics
            issues (list): List of issues detected
            timeframe (tuple): Start and end time of the analysis period
            
        Returns:
            bool: True if email was sent successfully
        """
        start_time, end_time = timeframe
        subject = f"Daily Log Analysis Summary: {start_time.strftime('%Y-%m-%d')}"
        
        content = f"Log Analysis Summary for period: {start_time.strftime('%Y-%m-%d %H:%M')} to {end_time.strftime('%Y-%m-%d %H:%M')}\n\n"
        
        # Format the data
        summary_data = {
            'Analysis Period': f"{start_time.strftime('%Y-%m-%d %H:%M')} to {end_time.strftime('%Y-%m-%d %H:%M')}",
            'Total Logs Processed': stats.get('total_logs', 0),
            'Unique IP Addresses': stats.get('unique_ips', 0),
            'Average Response Time': f"{stats.get('avg_response_time', 0):.3f}s",
            'Error Rate': f"{stats.get('error_rate', 0):.2%}",
            'Security Events': stats.get('security_events', 0),
            'Performance Issues': stats.get('performance_issues', 0),
            'Anomalies Detected': stats.get('anomalies', 0)
        }
        
        return self.send_alert(subject, content, summary_data, alert_type='daily_summary')
