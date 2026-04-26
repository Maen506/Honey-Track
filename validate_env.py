"""
Environment Configuration Validator
Validates and tests all .env configuration
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

class EnvironmentValidator:
    """Validate environment configuration"""
    
    def __init__(self):
        self.env_file = Path('.env')
        self.errors = []
        self.warnings = []
        self.success = []
    
    def load_env(self):
        """Load environment variables"""
        if not self.env_file.exists():
            self.errors.append("❌ .env file not found. Run: cp .env.example .env")
            return False
        
        load_dotenv(self.env_file)
        self.success.append("✓ .env file loaded")
        return True
    
    def validate_database(self):
        """Validate database configuration"""
        print("\n📊 Validating Database Configuration...")
        
        required = ['DB_HOST', 'DB_PORT', 'DB_USER', 'DB_PASSWORD', 'DB_NAME']
        
        for var in required:
            value = os.getenv(var)
            if not value:
                self.errors.append(f"❌ Missing: {var}")
            else:
                self.success.append(f"✓ {var}: {value if var != 'DB_PASSWORD' else '***'}")
        
        # Try to connect
        try:
            import mysql.connector
            
            conn = mysql.connector.connect(
                host=os.getenv('DB_HOST'),
                port=int(os.getenv('DB_PORT', 3306)),
                user=os.getenv('DB_USER'),
                password=os.getenv('DB_PASSWORD')
            )
            
            self.success.append("✓ Database connection successful")
            conn.close()
        except Exception as e:
            self.warnings.append(f"⚠️  Database connection failed: {str(e)}")
    
    def validate_virustotal(self):
        """Validate VirusTotal configuration"""
        print("\n🔍 Validating VirusTotal Configuration...")
        
        api_key = os.getenv('VIRUSTOTAL_API_KEY')
        
        if not api_key:
            self.errors.append("❌ Missing: VIRUSTOTAL_API_KEY")
            return
        
        if api_key == 'your_virustotal_api_key_here':
            self.errors.append("❌ VIRUSTOTAL_API_KEY not configured (still has default value)")
            return
        
        self.success.append(f"✓ VIRUSTOTAL_API_KEY configured")
        
        # Test API
        try:
            import requests
            
            headers = {'x-apikey': api_key}
            response = requests.get(
                'https://www.virustotal.com/api/v3/domains/google.com',
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                self.success.append("✓ VirusTotal API key is valid")
            elif response.status_code == 401:
                self.errors.append("❌ VirusTotal API key is invalid (401 Unauthorized)")
            else:
                self.warnings.append(f"⚠️  VirusTotal API returned status {response.status_code}")
        
        except Exception as e:
            self.warnings.append(f"⚠️  Could not test VirusTotal API: {str(e)}")
    
    def validate_flask(self):
        """Validate Flask configuration"""
        print("\n🌐 Validating Flask Configuration...")
        
        required = ['FLASK_PORT', 'FLASK_ENV', 'SECRET_KEY']
        
        for var in required:
            value = os.getenv(var)
            if not value:
                self.errors.append(f"❌ Missing: {var}")
            else:
                display_value = value if var != 'SECRET_KEY' else '***'
                self.success.append(f"✓ {var}: {display_value}")
        
        # Check if port is available
        try:
            import socket
            
            port = int(os.getenv('FLASK_PORT', 5000))
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            
            if result == 0:
                self.warnings.append(f"⚠️  Port {port} is already in use")
            else:
                self.success.append(f"✓ Flask port {port} is available")
        
        except Exception as e:
            self.warnings.append(f"⚠️  Could not check Flask port: {str(e)}")
    
    def validate_honeypots(self):
        """Validate honeypot configuration"""
        print("\n🍯 Validating Honeypot Configuration...")
        
        ssh_port = int(os.getenv('SSH_PORT', 2222))
        http_port = int(os.getenv('HTTP_PORT', 8080))
        
        self.success.append(f"✓ SSH Port: {ssh_port}")
        self.success.append(f"✓ HTTP Port: {http_port}")
        
        # Check if ports are available
        try:
            import socket
            
            for port, name in [(ssh_port, 'SSH'), (http_port, 'HTTP')]:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                
                if result == 0:
                    self.warnings.append(f"⚠️  {name} port {port} is already in use")
                else:
                    self.success.append(f"✓ {name} port {port} is available")
        
        except Exception as e:
            self.warnings.append(f"⚠️  Could not check honeypot ports: {str(e)}")
    
    def validate_ml(self):
        """Validate ML configuration"""
        print("\n🤖 Validating ML Configuration...")
        
        ml_enabled = os.getenv('ML_ENABLED', 'True') == 'True'
        
        if ml_enabled:
            self.success.append("✓ ML is enabled")
            
            # Check if models exist
            model_path = Path(os.getenv('ML_MODEL_PATH', 'ml/models'))
            
            if model_path.exists():
                models = list(model_path.glob('*.pkl'))
                
                self.success.append(f"✓ Found {len(models)} ML models")
            else:
                self.warnings.append(f"⚠️  ML models directory not found: {model_path}")
        else:
            self.warnings.append("⚠️  ML is disabled")
    
    def validate_mitre(self):
        """Validate MITRE configuration"""
        print("\n🎯 Validating MITRE Configuration...")
        
        mitre_enabled = os.getenv('MITRE_ENABLED', 'True') == 'True'
        
        if mitre_enabled:
            self.success.append("✓ MITRE ATT&CK is enabled")
        else:
            self.warnings.append("⚠️  MITRE ATT&CK is disabled")
    
    def validate_logging(self):
        """Validate logging configuration"""
        print("\n📝 Validating Logging Configuration...")
        
        log_level = os.getenv('LOG_LEVEL', 'INFO')
        log_file = os.getenv('LOG_FILE', 'logs/honeytrack.log')
        
        self.success.append(f"✓ Log Level: {log_level}")
        self.success.append(f"✓ Log File: {log_file}")
        
        # Create log directory if needed
        log_dir = Path(log_file).parent
        if not log_dir.exists():
            try:
                log_dir.mkdir(parents=True, exist_ok=True)
                self.success.append(f"✓ Created log directory: {log_dir}")
            except Exception as e:
                self.warnings.append(f"⚠️  Could not create log directory: {str(e)}")
    
    def print_report(self):
        """Print validation report"""
        print("\n" + "=" * 60)
        print("ENVIRONMENT CONFIGURATION VALIDATION REPORT")
        print("=" * 60)
        
        if self.success:
            print("\n✅ SUCCESS:")
            for msg in self.success:
                print(f"  {msg}")
        
        if self.warnings:
            print("\n⚠️  WARNINGS:")
            for msg in self.warnings:
                print(f"  {msg}")
        
        if self.errors:
            print("\n❌ ERRORS:")
            for msg in self.errors:
                print(f"  {msg}")
        
        print("\n" + "=" * 60)
        
        if self.errors:
            print("❌ Validation FAILED - Please fix errors above")
            return False
        else:
            print("✅ Validation PASSED - Configuration is ready!")
            return True
    
    def validate_all(self):
        """Run all validations"""
        if not self.load_env():
            self.print_report()
            return False
        
        self.validate_database()
        self.validate_virustotal()
        self.validate_flask()
        self.validate_honeypots()
        self.validate_ml()
        self.validate_mitre()
        self.validate_logging()
        
        return self.print_report()

def main():
    """Main function"""
    validator = EnvironmentValidator()
    success = validator.validate_all()
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
