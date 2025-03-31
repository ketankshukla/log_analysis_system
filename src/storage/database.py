"""
Database operations for the Log Analysis & Monitoring System.
"""
import os
import sqlite3
import logging
import pandas as pd
from pathlib import Path
from ..utils.helpers import ensure_dir_exists

logger = logging.getLogger(__name__)

class LogDatabase:
    """
    SQLite database handler for storing and retrieving processed log data.
    """
    
    def __init__(self, db_path):
        """
        Initialize the database connection.
        
        Args:
            db_path (str): Path to the SQLite database file
        """
        self.db_path = db_path
        self.conn = None
        
        # Ensure the directory exists
        ensure_dir_exists(os.path.dirname(db_path))
        
        # Initialize database
        self._connect()
        self._create_tables()
        
        logger.info(f"Database initialized at {db_path}")
    
    def _connect(self):
        """Establish a connection to the SQLite database."""
        try:
            self.conn = sqlite3.connect(self.db_path)
            # Enable foreign keys
            self.conn.execute("PRAGMA foreign_keys = ON")
            # Set row factory to return rows as dictionaries
            self.conn.row_factory = sqlite3.Row
        except sqlite3.Error as e:
            logger.error(f"Database connection error: {str(e)}")
            raise
    
    def _create_tables(self):
        """Create database tables if they don't exist."""
        try:
            cursor = self.conn.cursor()
            
            # Create access logs table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS access_logs (
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
                log_format TEXT,
                log_type TEXT,
                source_file TEXT,
                processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            # Create error logs table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS error_logs (
                id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                level TEXT,
                module TEXT,
                pid TEXT,
                message TEXT,
                log_type TEXT,
                source_file TEXT,
                processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            # Create performance metrics table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                metric_name TEXT NOT NULL,
                metric_value REAL,
                endpoint TEXT,
                time_window INTEGER,
                source_file TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            # Create security events table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT,
                ip_address TEXT,
                endpoint TEXT,
                description TEXT,
                source_file TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            # Create anomalies table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                metric_name TEXT NOT NULL,
                expected_value REAL,
                actual_value REAL,
                z_score REAL,
                source_file TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            # Create indexes for faster queries
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_access_logs_timestamp ON access_logs(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_access_logs_ip ON access_logs(ip_address)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_access_logs_endpoint ON access_logs(endpoint)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_error_logs_timestamp ON error_logs(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_performance_metrics_timestamp ON performance_metrics(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_anomalies_timestamp ON anomalies(timestamp)')
            
            self.conn.commit()
            
        except sqlite3.Error as e:
            logger.error(f"Error creating database tables: {str(e)}")
            raise
    
    def store_access_logs(self, logs_data, source_file=None):
        """
        Store access log entries in the database.
        
        Args:
            logs_data (list): List of dictionaries containing log data
            source_file (str): Source log file name
            
        Returns:
            int: Number of records inserted
        """
        if not logs_data:
            return 0
            
        try:
            # Convert to DataFrame for efficient bulk insert
            df = pd.DataFrame(logs_data)
            
            # Add source file information
            if source_file:
                df['source_file'] = source_file
            
            # Insert into database
            with self.conn:
                count = df.to_sql('access_logs', self.conn, if_exists='append', index=False)
                
            logger.info(f"Stored {count} access log entries from {source_file or 'unknown source'}")
            return count
            
        except Exception as e:
            logger.error(f"Error storing access logs: {str(e)}")
            return 0
    
    def store_error_logs(self, logs_data, source_file=None):
        """
        Store error log entries in the database.
        
        Args:
            logs_data (list): List of dictionaries containing log data
            source_file (str): Source log file name
            
        Returns:
            int: Number of records inserted
        """
        if not logs_data:
            return 0
            
        try:
            # Convert to DataFrame for efficient bulk insert
            df = pd.DataFrame(logs_data)
            
            # Add source file information
            if source_file:
                df['source_file'] = source_file
            
            # Insert into database
            with self.conn:
                count = df.to_sql('error_logs', self.conn, if_exists='append', index=False)
                
            logger.info(f"Stored {count} error log entries from {source_file or 'unknown source'}")
            return count
            
        except Exception as e:
            logger.error(f"Error storing error logs: {str(e)}")
            return 0
    
    def store_performance_metrics(self, metrics_data):
        """
        Store performance metrics in the database.
        
        Args:
            metrics_data (list): List of dictionaries containing metrics
            
        Returns:
            int: Number of records inserted
        """
        if not metrics_data:
            return 0
            
        try:
            # Convert to DataFrame for efficient bulk insert
            df = pd.DataFrame(metrics_data)
            
            # Insert into database
            with self.conn:
                count = df.to_sql('performance_metrics', self.conn, if_exists='append', index=False)
                
            logger.info(f"Stored {count} performance metrics")
            return count
            
        except Exception as e:
            logger.error(f"Error storing performance metrics: {str(e)}")
            return 0
    
    def store_security_events(self, events_data):
        """
        Store security events in the database.
        
        Args:
            events_data (list): List of dictionaries containing security events
            
        Returns:
            int: Number of records inserted
        """
        if not events_data:
            return 0
            
        try:
            # Convert to DataFrame for efficient bulk insert
            df = pd.DataFrame(events_data)
            
            # Insert into database
            with self.conn:
                count = df.to_sql('security_events', self.conn, if_exists='append', index=False)
                
            logger.info(f"Stored {count} security events")
            return count
            
        except Exception as e:
            logger.error(f"Error storing security events: {str(e)}")
            return 0
    
    def store_anomalies(self, anomalies_data):
        """
        Store detected anomalies in the database.
        
        Args:
            anomalies_data (list): List of dictionaries containing anomaly data
            
        Returns:
            int: Number of records inserted
        """
        if not anomalies_data:
            return 0
            
        try:
            # Convert to DataFrame for efficient bulk insert
            df = pd.DataFrame(anomalies_data)
            
            # Insert into database
            with self.conn:
                count = df.to_sql('anomalies', self.conn, if_exists='append', index=False)
                
            logger.info(f"Stored {count} anomalies")
            return count
            
        except Exception as e:
            logger.error(f"Error storing anomalies: {str(e)}")
            return 0
    
    def get_logs_by_timeframe(self, start_time, end_time, table='access_logs'):
        """
        Retrieve logs within a specific timeframe.
        
        Args:
            start_time (str): Start of timeframe (ISO format)
            end_time (str): End of timeframe (ISO format)
            table (str): Table to query ('access_logs' or 'error_logs')
            
        Returns:
            pandas.DataFrame: Retrieved logs
        """
        query = f"""
        SELECT * FROM {table} 
        WHERE timestamp BETWEEN ? AND ?
        ORDER BY timestamp
        """
        
        try:
            return pd.read_sql_query(query, self.conn, params=(start_time, end_time))
        except Exception as e:
            logger.error(f"Error retrieving logs by timeframe: {str(e)}")
            return pd.DataFrame()
    
    def get_response_time_stats_by_endpoint(self, start_time=None, end_time=None):
        """
        Get response time statistics grouped by endpoint.
        
        Args:
            start_time (str): Optional start of timeframe (ISO format)
            end_time (str): Optional end of timeframe (ISO format)
            
        Returns:
            pandas.DataFrame: Response time statistics
        """
        query = """
        SELECT 
            endpoint,
            COUNT(*) as requests,
            AVG(response_time) as avg_response_time,
            MIN(response_time) as min_response_time,
            MAX(response_time) as max_response_time,
            SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) as error_count
        FROM access_logs
        """
        
        params = []
        
        if start_time or end_time:
            query += " WHERE "
            if start_time:
                query += "timestamp >= ?"
                params.append(start_time)
            if start_time and end_time:
                query += " AND "
            if end_time:
                query += "timestamp <= ?"
                params.append(end_time)
        
        query += " GROUP BY endpoint ORDER BY avg_response_time DESC"
        
        try:
            return pd.read_sql_query(query, self.conn, params=params)
        except Exception as e:
            logger.error(f"Error retrieving response time stats: {str(e)}")
            return pd.DataFrame()
    
    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()
            logger.debug("Database connection closed")
    
    def __enter__(self):
        """Context manager enter method."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit method."""
        self.close()
