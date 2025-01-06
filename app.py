from flask import Flask, jsonify, render_template, request, send_from_directory
from werkzeug.utils import secure_filename
import os
import subprocess
import logging

# Initialize Flask app
app = Flask(__name__, static_folder='static')

# Configuration
class Config:
    # Upload configuration
    UPLOAD_FOLDER = './uploads'
    ALLOWED_EXTENSIONS = {'py'}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB limit
    
    # Security configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-please-change-in-production'
    
    # Bandit configuration
    BANDIT_OPTIONS = [
        '-f', 'json',  # Output format
        '-ll', 'ALL',  # Log level
        '--recursive'  # Scan directories recursively
    ]

# Apply configuration
app.config.from_object(Config)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create upload directory if it doesn't exist
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

class VulnerabilityScanner:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def allowed_file(self, filename):
        return '.' in filename and \
            filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS
    
    def process_file(self, request):
        # Check if file exists in request
        if 'file' not in request.files:
            self.logger.error('No file part in request')
            return jsonify(status='error', error='No file part'), 400
        
        file = request.files['file']
        
        # Check if file was selected
        if file.filename == '':
            self.logger.error('No selected file')
            return jsonify(status='error', error='No selected file'), 400
        
        # Validate file type
        if not self.allowed_file(file.filename):
            self.logger.error(f'Invalid file type: {file.filename}')
            return jsonify(status='error', error='Invalid file type'), 400
        
        try:
            # Save file securely
            filename = secure_filename(file.filename)
            filepath = os.path.join(Config.UPLOAD_FOLDER, filename)
            file.save(filepath)
            self.logger.info(f'File saved: {filepath}')
            
            # Run security scan
            scan_result = self.run_security_scan(filepath)
            
            # Clean up
            os.remove(filepath)
            self.logger.info(f'File removed: {filepath}')
            
            return scan_result
            
        except Exception as e:
            self.logger.error(f'Error processing file: {str(e)}')
            if os.path.exists(filepath):
                os.remove(filepath)
            raise
    
    def run_security_scan(self, filepath):
        try:
            # Run Bandit security scanner
            cmd = ['bandit', filepath] + Config.BANDIT_OPTIONS
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                self.logger.info('Security scan completed successfully')
                return jsonify(status='success', output=result.stdout), 200
            else:
                self.logger.error(f'Security scan failed: {result.stderr}')
                return jsonify(status='error', error=result.stderr), 500
                
        except Exception as e:
            self.logger.error(f'Error running security scan: {str(e)}')
            raise

# Initialize scanner
scanner = VulnerabilityScanner()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

@app.route('/scan', methods=['POST'])
def scan():
    try:
        return scanner.process_file(request)
    except Exception as e:
        logger.error(f'Scan error: {str(e)}')
        return jsonify(status='error', error=str(e)), 500

if __name__ == '__main__':
    app.run(debug=True)
