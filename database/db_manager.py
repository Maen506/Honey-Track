"""Database Manager - All MySQL operations"""

import mysql.connector
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class DatabaseManager:
    """MySQL Database Manager"""
    
    def __init__(self, host, port, user, password, database):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self.connection = None
    
    def connect(self) -> bool:
        """Connect to database"""
        try:
            self.connection = mysql.connector.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                database=self.database
            )
            logger.info("Database connected")
            return True
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from database"""
        if self.connection:
            self.connection.close()
            logger.info("Database disconnected")
    
    def execute(self, query: str, params: tuple = ()) -> bool:
        """Execute query"""
        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params)
            self.connection.commit()
            cursor.close()
            return True
        except Exception as e:
            logger.error(f"Query execution failed: {e}")
            return False
    
    def fetch_one(self, query: str, params: tuple = ()) -> Optional[tuple]:
        """Fetch one row"""
        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params)
            result = cursor.fetchone()
            cursor.close()
            return result
        except Exception as e:
            logger.error(f"Fetch failed: {e}")
            return None
    
    def fetch_all(self, query: str, params: tuple = ()) -> List[tuple]:
        """Fetch all rows"""
        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params)
            result = cursor.fetchall()
            cursor.close()
            return result
        except Exception as e:
            logger.error(f"Fetch failed: {e}")
            return []
    
    def log_attack(self, source_ip: str, attack_type: str, details: str) -> bool:
        """Log attack to database"""
        query = """
        INSERT INTO attacks (source_ip, attack_type, details, timestamp)
        VALUES (%s, %s, %s, NOW())
        """
        return self.execute(query, (source_ip, attack_type, details))
    
    def get_stats(self) -> Dict[str, Any]:
        """Get attack statistics"""
        try:
            total = self.fetch_one("SELECT COUNT(*) FROM attacks")[0]
            today = self.fetch_one(
                "SELECT COUNT(*) FROM attacks WHERE DATE(timestamp) = CURDATE()"
            )[0]
            
            return {
                'total_attacks': total,
                'today_attacks': today
            }
        except:
            return {'total_attacks': 0, 'today_attacks': 0}

db_manager = None
