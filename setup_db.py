"""
Setup Database - Run once to create tables
"""

import mysql.connector
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def setup_database():
    """Create database and tables"""
    
    conn = mysql.connector.connect(
        host='localhost',
        user='root',
        password=''
    )
    
    cursor = conn.cursor()
    
    # Create database
    cursor.execute("CREATE DATABASE IF NOT EXISTS honeypot_db CHARACTER SET utf8mb4")
    logger.info("✓ Database created")
    
    # Use database
    cursor.execute("USE honeypot_db")
    
    # Create tables
    tables = [
        """CREATE TABLE IF NOT EXISTS attacks (
            id INT AUTO_INCREMENT PRIMARY KEY,
            source_ip VARCHAR(45) NOT NULL,
            attack_type VARCHAR(50),
            details TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_ip (source_ip),
            INDEX idx_type (attack_type),
            INDEX idx_time (timestamp)
        )""",
        
        """CREATE TABLE IF NOT EXISTS logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            attack_id INT,
            event_type VARCHAR(50),
            data TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (attack_id) REFERENCES attacks(id),
            INDEX idx_type (event_type)
        )""",
        
        """CREATE TABLE IF NOT EXISTS alerts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            attack_id INT,
            severity VARCHAR(20),
            message TEXT,
            sent BOOLEAN DEFAULT FALSE,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (attack_id) REFERENCES attacks(id),
            INDEX idx_severity (severity)
        )"""
    ]
    
    for table in tables:
        cursor.execute(table)
        logger.info("✓ Table created")
    
    conn.commit()
    cursor.close()
    conn.close()
    
    logger.info("✓ Database setup complete!")

if __name__ == '__main__':
    setup_database()
