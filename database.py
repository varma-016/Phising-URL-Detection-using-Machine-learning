"""
SQLite Database Module for Phishing URL Detection System
Manages data persistence for scanned URLs and predictions
"""

import sqlite3
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PhishingDetectionDatabase:
    """
    SQLite database for storing phishing detection results
    """
    
    def __init__(self, db_path: str = "data/phishing_detection.db"):
        """Initialize database connection"""
        self.db_path = db_path
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._create_tables()
    
    def _get_connection(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _create_tables(self):
        """Create necessary database tables"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Predictions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS predictions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL UNIQUE,
                prediction INTEGER NOT NULL,
                confidence REAL NOT NULL,
                model_name TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                features_json TEXT
            )
        ''')
        
        # Scan history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                is_phishing INTEGER NOT NULL,
                model_used TEXT NOT NULL,
                confidence REAL NOT NULL,
                processing_time_ms REAL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Models table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS models (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_name TEXT NOT NULL UNIQUE,
                model_type TEXT NOT NULL,
                accuracy REAL,
                precision REAL,
                recall REAL,
                f1_score REAL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME
            )
        ''')
        
        # Create indexes for faster queries
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_url ON predictions(url)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON predictions(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_url ON scan_history(url)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON scan_history(timestamp)')
        
        conn.commit()
        conn.close()
        logger.info(f"Database initialized at {self.db_path}")
    
    def store_prediction(self, url: str, prediction: int, confidence: float, 
                        model_name: str, features: Dict = None) -> bool:
        """
        Store prediction result in database
        
        Args:
            url: The URL that was scanned
            prediction: 1 for phishing, 0 for legitimate
            confidence: Confidence score (0-1)
            model_name: Name of the model used
            features: Dictionary of extracted features
        
        Returns:
            bool: Success status
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            features_json = json.dumps(features) if features else None
            
            cursor.execute('''
                INSERT OR REPLACE INTO predictions 
                (url, prediction, confidence, model_name, features_json)
                VALUES (?, ?, ?, ?, ?)
            ''', (url, prediction, confidence, model_name, features_json))
            
            conn.commit()
            conn.close()
            logger.info(f"Stored prediction for {url}")
            return True
        except Exception as e:
            logger.error(f"Error storing prediction: {str(e)}")
            return False
    
    def store_scan_result(self, url: str, is_phishing: int, model_used: str, 
                         confidence: float, processing_time_ms: float = None) -> bool:
        """
        Store scan result in history table
        
        Args:
            url: The URL that was scanned
            is_phishing: 1 for phishing, 0 for legitimate
            model_used: Name of model used
            confidence: Confidence score
            processing_time_ms: Time taken to process in milliseconds
        
        Returns:
            bool: Success status
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO scan_history 
                (url, is_phishing, model_used, confidence, processing_time_ms)
                VALUES (?, ?, ?, ?, ?)
            ''', (url, is_phishing, model_used, confidence, processing_time_ms))
            
            conn.commit()
            conn.close()
            logger.info(f"Stored scan result for {url}")
            return True
        except Exception as e:
            logger.error(f"Error storing scan result: {str(e)}")
            return False
    
    def store_model_metrics(self, model_name: str, model_type: str, 
                           accuracy: float, precision: float, 
                           recall: float, f1_score: float) -> bool:
        """
        Store model performance metrics
        
        Args:
            model_name: Name of the model
            model_type: Type (e.g., 'random_forest', 'xgboost', 'cnn', 'lstm')
            accuracy, precision, recall, f1_score: Performance metrics
        
        Returns:
            bool: Success status
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO models 
                (model_name, model_type, accuracy, precision, recall, f1_score, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (model_name, model_type, accuracy, precision, recall, f1_score))
            
            conn.commit()
            conn.close()
            logger.info(f"Stored metrics for {model_name}")
            return True
        except Exception as e:
            logger.error(f"Error storing model metrics: {str(e)}")
            return False
    
    def get_prediction(self, url: str) -> Optional[Dict]:
        """
        Get stored prediction for a URL
        
        Args:
            url: The URL to lookup
        
        Returns:
            Dictionary with prediction data or None
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM predictions WHERE url = ?
            ''', (url,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return dict(result)
            return None
        except Exception as e:
            logger.error(f"Error retrieving prediction: {str(e)}")
            return None
    
    def get_scan_history(self, limit: int = 100, days: int = 30) -> List[Dict]:
        """
        Get recent scan history
        
        Args:
            limit: Maximum number of records to return
            days: Number of days to look back
        
        Returns:
            List of scan history records
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM scan_history 
                WHERE timestamp >= datetime('now', '-' || ? || ' days')
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (days, limit))
            
            results = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return results
        except Exception as e:
            logger.error(f"Error retrieving scan history: {str(e)}")
            return []
    
    def get_model_metrics(self, model_name: str = None) -> Optional[Dict]:
        """
        Get model performance metrics
        
        Args:
            model_name: Optional specific model name
        
        Returns:
            Model metrics or list of metrics
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            if model_name:
                cursor.execute('''
                    SELECT * FROM models WHERE model_name = ?
                ''', (model_name,))
                result = cursor.fetchone()
                conn.close()
                return dict(result) if result else None
            else:
                cursor.execute('SELECT * FROM models ORDER BY updated_at DESC')
                results = [dict(row) for row in cursor.fetchall()]
                conn.close()
                return results
        except Exception as e:
            logger.error(f"Error retrieving model metrics: {str(e)}")
            return None
    
    def get_statistics(self) -> Dict:
        """
        Get database statistics
        
        Returns:
            Dictionary with various statistics
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Total predictions
            cursor.execute('SELECT COUNT(*) as count FROM predictions')
            total_predictions = cursor.fetchone()['count']
            
            # Phishing detections
            cursor.execute('SELECT COUNT(*) as count FROM predictions WHERE prediction = 1')
            phishing_count = cursor.fetchone()['count']
            
            # Recent scans (last 24 hours)
            cursor.execute('''
                SELECT COUNT(*) as count FROM scan_history 
                WHERE timestamp >= datetime('now', '-1 day')
            ''')
            recent_scans = cursor.fetchone()['count']
            
            # Models count
            cursor.execute('SELECT COUNT(*) as count FROM models')
            models_count = cursor.fetchone()['count']
            
            conn.close()
            
            return {
                'total_predictions': total_predictions,
                'phishing_detected': phishing_count,
                'legitimate_detected': total_predictions - phishing_count,
                'recent_scans_24h': recent_scans,
                'models_trained': models_count,
                'detection_rate': (phishing_count / total_predictions * 100) if total_predictions > 0 else 0
            }
        except Exception as e:
            logger.error(f"Error getting statistics: {str(e)}")
            return {}


if __name__ == "__main__":
    # Example usage
    db = PhishingDetectionDatabase()
    
    # Test storing a prediction
    db.store_prediction(
        url="https://malicious-site.com",
        prediction=1,
        confidence=0.95,
        model_name="random_forest_v1"
    )
    
    # Get statistics
    stats = db.get_statistics()
    print("Database Statistics:")
    print(json.dumps(stats, indent=2))
