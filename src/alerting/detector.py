"""
Anomaly detector for the Log Analysis & Monitoring System.

This module provides functionality for detecting anomalies in log data using
statistical methods and machine learning techniques.
"""
import logging
import numpy as np
import pandas as pd
from datetime import datetime
from scipy import stats

logger = logging.getLogger(__name__)

class AnomalyDetector:
    """
    Detects anomalies in time series data from logs using statistical methods.
    """
    
    def __init__(self, config):
        """
        Initialize the anomaly detector.
        
        Args:
            config (dict): Configuration dictionary
        """
        self.config = config
        self.anomaly_config = config.get('anomaly_detection', {})
        self.z_threshold = self.anomaly_config.get('z_score_threshold', 3.0)
        self.min_data_points = self.anomaly_config.get('min_data_points', 10)
        self.window_size = self.anomaly_config.get('window_size', 3600)  # in seconds
        
        logger.debug(f"Anomaly detector initialized with z-score threshold: {self.z_threshold}")
    
    def detect_response_time_anomalies(self, data):
        """
        Detect anomalies in response time data using z-score method.
        
        Args:
            data (numpy.ndarray or list): Response time data points
            
        Returns:
            list: Indices of anomalous data points
        """
        if len(data) < self.min_data_points:
            logger.warning(f"Not enough data points for anomaly detection: {len(data)} < {self.min_data_points}")
            return []
        
        try:
            # Convert to numpy array if necessary
            data_array = np.array(data)
            
            # Calculate z-scores
            z_scores = np.abs(stats.zscore(data_array))
            
            # Find indices of anomalies
            anomalies = np.where(z_scores > self.z_threshold)[0]
            
            logger.info(f"Detected {len(anomalies)} anomalies in {len(data)} data points using z-score method")
            return anomalies.tolist()
            
        except Exception as e:
            logger.error(f"Error detecting response time anomalies: {str(e)}")
            return []
    
    def detect_traffic_anomalies(self, time_series):
        """
        Detect anomalies in traffic patterns over time.
        
        Args:
            time_series (pandas.Series): Time series data of request counts
            
        Returns:
            list: Timestamps of anomalous traffic
        """
        if len(time_series) < self.min_data_points:
            logger.warning(f"Not enough data points for traffic anomaly detection: {len(time_series)} < {self.min_data_points}")
            return []
        
        try:
            # Calculate moving average and standard deviation
            rolling_mean = time_series.rolling(window=5, min_periods=3).mean()
            rolling_std = time_series.rolling(window=5, min_periods=3).std()
            
            # Fill NaN values
            rolling_mean = rolling_mean.fillna(time_series.mean())
            rolling_std = rolling_std.fillna(time_series.std())
            
            # Calculate upper and lower bounds
            upper_bound = rolling_mean + self.z_threshold * rolling_std
            lower_bound = rolling_mean - self.z_threshold * rolling_std
            
            # Find anomalies
            anomalies = time_series[(time_series > upper_bound) | (time_series < lower_bound)]
            
            logger.info(f"Detected {len(anomalies)} traffic anomalies in {len(time_series)} time points")
            return anomalies.index.tolist()
            
        except Exception as e:
            logger.error(f"Error detecting traffic anomalies: {str(e)}")
            return []
    
    def detect_error_rate_anomalies(self, error_rates):
        """
        Detect anomalies in error rates.
        
        Args:
            error_rates (pandas.Series): Time series data of error rates
            
        Returns:
            list: Timestamps of anomalous error rates
        """
        if len(error_rates) < self.min_data_points:
            logger.warning(f"Not enough data points for error rate anomaly detection: {len(error_rates)} < {self.min_data_points}")
            return []
        
        try:
            # Use percentile-based detection for error rates
            q75 = np.percentile(error_rates, 75)
            q25 = np.percentile(error_rates, 25)
            iqr = q75 - q25
            
            # Define bounds as 1.5 * IQR beyond the quartiles (standard for box plots)
            upper_bound = q75 + 1.5 * iqr
            
            # For error rates, we're primarily concerned with high values
            anomalies = error_rates[error_rates > upper_bound]
            
            logger.info(f"Detected {len(anomalies)} error rate anomalies in {len(error_rates)} time points")
            return anomalies.index.tolist()
            
        except Exception as e:
            logger.error(f"Error detecting error rate anomalies: {str(e)}")
            return []
    
    def prepare_anomaly_records(self, anomalies, data, metric_name, timestamps=None, source=None):
        """
        Prepare anomaly records for storage in database.
        
        Args:
            anomalies (list): Indices or timestamps of anomalous data points
            data (numpy.ndarray or pandas.Series): The data being analyzed
            metric_name (str): Name of the metric (e.g., 'response_time')
            timestamps (list, optional): Timestamps corresponding to data points
            source (str, optional): Source of the data
            
        Returns:
            list: List of dicts containing anomaly records
        """
        records = []
        current_time = datetime.now().isoformat()
        
        # Calculate basic statistics for reference
        if len(data) > 0:
            mean_value = np.mean(data)
            std_value = np.std(data)
        else:
            mean_value = 0
            std_value = 0
        
        for anomaly in anomalies:
            try:
                # Get the anomalous value and its timestamp
                if isinstance(data, pd.Series) and isinstance(anomaly, (pd.Timestamp, str)):
                    # If we have a pandas Series and timestamp-based anomaly
                    value = data[anomaly]
                    timestamp = anomaly
                elif timestamps and isinstance(anomaly, int) and anomaly < len(timestamps):
                    # If we have separate timestamps list and index-based anomaly
                    value = data[anomaly]
                    timestamp = timestamps[anomaly]
                else:
                    # Default case with just indices
                    value = data[anomaly]
                    timestamp = current_time
                
                # Calculate z-score
                if std_value > 0:
                    z_score = (value - mean_value) / std_value
                else:
                    z_score = 0
                
                # Create record
                records.append({
                    'timestamp': timestamp if isinstance(timestamp, str) else timestamp.isoformat(),
                    'metric_name': metric_name,
                    'expected_value': float(mean_value),
                    'actual_value': float(value),
                    'z_score': float(z_score),
                    'source_file': source
                })
                
            except Exception as e:
                logger.error(f"Error preparing anomaly record: {str(e)}")
        
        return records
    
    def analyze_logs(self, logs_df, timeframe=None):
        """
        Perform comprehensive anomaly detection analysis on log data.
        
        Args:
            logs_df (pandas.DataFrame): DataFrame containing parsed logs
            timeframe (tuple, optional): Start and end timestamps for analysis
            
        Returns:
            dict: Results of anomaly detection
        """
        if logs_df.empty:
            logger.warning("No log data available for anomaly detection")
            return {
                'anomalies_detected': 0,
                'anomaly_records': []
            }
        
        all_anomaly_records = []
        
        # Detect response time anomalies if data available
        if 'response_time' in logs_df.columns:
            response_times = logs_df['response_time'].values
            anomaly_indices = self.detect_response_time_anomalies(response_times)
            
            if anomaly_indices:
                # Get timestamps if available
                timestamps = None
                if 'timestamp' in logs_df.columns:
                    timestamps = logs_df['timestamp'].tolist()
                
                # Prepare records
                records = self.prepare_anomaly_records(
                    anomaly_indices, 
                    response_times, 
                    'response_time',
                    timestamps
                )
                all_anomaly_records.extend(records)
        
        # Detect error rate anomalies if we have enough data points
        if 'timestamp' in logs_df.columns and 'status' in logs_df.columns and len(logs_df) >= self.min_data_points:
            try:
                # Create a time series of error rates
                logs_df['is_error'] = logs_df['status'] >= 400
                error_series = logs_df.resample('5min', on='timestamp')['is_error'].mean()
                
                # Detect anomalies
                anomaly_timestamps = self.detect_error_rate_anomalies(error_series)
                
                if anomaly_timestamps:
                    # Prepare records
                    records = self.prepare_anomaly_records(
                        anomaly_timestamps,
                        error_series,
                        'error_rate'
                    )
                    all_anomaly_records.extend(records)
            except Exception as e:
                logger.error(f"Error analyzing error rates: {str(e)}")
        
        # Return results
        return {
            'anomalies_detected': len(all_anomaly_records),
            'anomaly_records': all_anomaly_records
        }
