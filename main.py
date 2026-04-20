"""
HoneyTrack - Main Entry Point
Runs everything: SSH Honeypot, HTTP Honeypot, Flask Dashboard
"""

import os
import sys
import logging
import threading
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template_string
from core.ssh_honeypot import ssh_honeypot
from core.http_honeypot import http_honeypot
from core.event_queue import event_queue
from database.db_manager import DatabaseManager
from virustotal.vt_client import VirusTotalClient

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/honeytrack.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key')

# Global variables
db = None
vt = None

@app.route('/')
def dashboard():
    """Main dashboard"""
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>HoneyTrack Dashboard</title>
        <style>
            body { font-family: Arial; margin: 20px; background: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; }
            h1 { color: #333; }
            .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 20px 0; }
            .stat-box { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .stat-value { font-size: 32px; font-weight: bold; color: #e74c3c; }
            .stat-label { color: #7f8c8d; margin-top: 10px; }
            .status { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; }
            .status-item { padding: 10px; border-bottom: 1px solid #ecf0f1; }
            .status-item:last-child { border-bottom: none; }
            .online { color: #27ae60; }
            .offline { color: #e74c3c; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🍯 HoneyTrack Dashboard</h1>
            
            <div class="stats">
                <div class="stat-box">
                    <div class="stat-value" id="total-attacks">0</div>
                    <div class="stat-label">Total Attacks</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value" id="today-attacks">0</div>
                    <div class="stat-label">Today's Attacks</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value" id="queue-size">0</div>
                    <div class="stat-label">Events in Queue</div>
                </div>
            </div>
            
            <div class="status">
                <h2>System Status</h2>
                <div class="status-item">
                    SSH Honeypot (Port 2222): <span class="online">● Running</span>
                </div>
                <div class="status-item">
                    HTTP Honeypot (Port 8080): <span class="online">● Running</span>
                </div>
                <div class="status-item">
                    Database: <span id="db-status" class="online">● Connected</span>
                </div>
                <div class="status-item">
                    VirusTotal API: <span id="vt-status" class="online">● Ready</span>
                </div>
            </div>
        </div>
        
        <script>
            setInterval(() => {
                fetch('/api/stats')
                    .then(r => r.json())
                    .then(d => {
                        document.getElementById('total-attacks').textContent = d.total_attacks;
                        document.getElementById('today-attacks').textContent = d.today_attacks;
                        document.getElementById('queue-size').textContent = d.queue_size;
                    });
            }, 2000);
        </script>
    </body>
    </html>
    ''')

@app.route('/api/stats')
def get_stats():
    """Get statistics"""
    stats = db.get_stats() if db else {'total_attacks': 0, 'today_attacks': 0}
    stats['queue_size'] = event_queue.size()
    return jsonify(stats)

def run_honeypots():
    """Run honeypots in background"""
    ssh_thread = threading.Thread(target=ssh_honeypot.start, daemon=True)
    http_thread = threading.Thread(target=http_honeypot.start, daemon=True)
    
    ssh_thread.start()
    http_thread.start()
    
    logger.info("Honeypots started")

def main():
    """Main function"""
    global db, vt
    
    logger.info("=" * 60)
    logger.info("HoneyTrack - Service-Emulating Honeypot")
    logger.info("=" * 60)
    
    # Initialize database
    try:
        db = DatabaseManager(
            host=os.getenv('DB_HOST', 'localhost'),
            port=int(os.getenv('DB_PORT', 3306)),
            user=os.getenv('DB_USER', 'root'),
            password=os.getenv('DB_PASSWORD', ''),
            database=os.getenv('DB_NAME', 'honeypot_db')
        )
        if db.connect():
            logger.info("✓ Database connected")
        else:
            logger.warning("⚠ Database connection failed")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
    
    # Initialize VirusTotal
    try:
        vt_key = os.getenv('VIRUSTOTAL_API_KEY')
        if vt_key:
            vt = VirusTotalClient(vt_key)
            logger.info("✓ VirusTotal client initialized")
        else:
            logger.warning("⚠ VirusTotal API key not configured")
    except Exception as e:
        logger.error(f"VirusTotal initialization failed: {e}")
    
    # Start honeypots
    run_honeypots()
    
    # Start Flask
    port = int(os.getenv('FLASK_PORT', 5000))
    logger.info(f"Starting Flask on port {port}...")
    logger.info(f"Open browser: http://localhost:{port}")
    
    app.run(host='0.0.0.0', port=port, debug=False)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        ssh_honeypot.stop()
        http_honeypot.stop()
        if db:
            db.disconnect()
        sys.exit(0)
