import os
import json
import subprocess
import logging
import tempfile
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory, session
import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from io import BytesIO

app = Flask(__name__, static_folder='static')

# Konfigurasi Flask dan MySQL
app = Flask(__name__)
app.secret_key = "supersecretkey" 

MYSQL_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'sastra_db'
}

def get_db_connection():
    try:
        connection = mysql.connector.connect(**MYSQL_CONFIG)
        return connection
    except Error as e:
        print(f"Error: {e}")
        return None

# Endpoint halaman utama
@app.route('/')
def home():
    return render_template('login.html')

# Endpoint untuk login
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()

    if user and check_password_hash(user['password'], password):
        session['username'] = user['username']
        flash("Login successful!", "success")
        cursor.close()
        connection.close()
        return redirect(url_for('dashboard'))
    else:
        flash("Invalid username or password.", "danger")
        cursor.close()
        connection.close()
        return redirect(url_for('home'))

# Endpoint untuk registrasi
@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    # Cek apakah username atau email sudah terdaftar
    cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
    existing_user = cursor.fetchone()

    if existing_user:
        flash("Username or email already exists.", "danger")
        cursor.close()
        connection.close()
        return redirect(url_for('home'))

    hashed_password = generate_password_hash(password)

    cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                (username, email, hashed_password))
    connection.commit()

    cursor.close()
    connection.close()
    flash("Registration successful! Please log in.", "success")
    return redirect(url_for('index.html'))

# Halaman dashboard (setelah login)
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('index.html')
    else:
        return redirect(url_for('login'))

# Logout endpoint
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('home'))


class Config:
    ALLOWED_EXTENSIONS = {'py'}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-please-change-in-production'
    
    BANDIT_OPTIONS = [
        '-f', 'json',
        '-ll', 'ALL',
        '--recursive'
    ]
    
app.config.from_object(Config)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
            # Save file to memory
            file_content = file.read()
            self.logger.info(f'File received: {file.filename}')
            
            # Run security scan
            scan_result = self.run_security_scan(file_content)
            
            return scan_result
            
        except Exception as e:
            self.logger.error(f'Error processing file: {str(e)}')
            return jsonify(status='error', error=str(e)), 500
    
    def run_security_scan(self, file_content):
        try:
            # Save file content to a temporary file on disk
            with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as temp_file:
                temp_file.write(file_content)
                temp_file.flush()
                temp_file_name = temp_file.name

            # Run Bandit security scanner
            cmd = ["bandit", "-f", "json", temp_file_name]
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False  # Don't raise exception on non-zero return code
            )

            # Clean up the temporary file
            os.remove(temp_file_name)

            # Parse the JSON output from Bandit
            try:
                if result.stdout:
                    scan_data = json.loads(result.stdout)
                    return jsonify(status='success', results=json.dumps(scan_data)), 200
                else:
                    # If no stdout but process completed
                    if result.returncode == 0:
                        return jsonify(status='success', results=json.dumps({'results': []})), 200
                    else:
                        # If there was an error
                        return jsonify(status='error', error=result.stderr), 500
            except json.JSONDecodeError:
                self.logger.error('Failed to parse Bandit output')
                return jsonify(status='error', error='Failed to parse scan results'), 500

        except Exception as e:
            self.logger.error(f'Error running security scan: {str(e)}')
            return jsonify(status='error', error=str(e)), 500

# Initialize scanner
scanner = VulnerabilityScanner()

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
    try:
        subprocess.run(['bandit', '--version'], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        logger.error("Bandit is not installed. Please install it using 'pip install bandit'")
        exit(1)
    except FileNotFoundError:
        logger.error("Bandit is not installed. Please install it using 'pip install bandit'")
        exit(1)
    app.run(debug=True)
