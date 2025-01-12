import os
import json
import subprocess
import logging
import tempfile
from flask import Flask, jsonify, render_template, request, redirect, url_for, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
import re

class DatabaseManager:
    def __init__(self):
        self.conn = None
        self.cursor = None

    def initialize_connection(self):
        try:
            self.conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="SASTRA"
            )
            self.cursor = self.conn.cursor()
            self.create_table()  # Pastikan tabel dibuat
            return True
        except mysql.connector.Error as e:
            print(f"Error during database connection: {e}")
            return False

    def create_table(self):
        try:
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) UNIQUE,
                    email VARCHAR(100) UNIQUE,
                    password VARCHAR(255),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            self.conn.commit()
        except mysql.connector.Error as e:
            print(f"Error creating table: {e}")

    def login_user(self, username, password):
        try:
            self.cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
            result = self.cursor.fetchone()
            if result and check_password_hash(result[0], password):
                return True
            return False
        except mysql.connector.Error as e:
            print(f"Login error: {e}")
            return False

    def register_user(self, username, email, password):
        try:
            hashed_password = generate_password_hash(password)
            print(f"Trying to insert: {username}, {email}, {hashed_password}")
            self.cursor.execute(
                "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                (username, email, hashed_password)
            )
            self.conn.commit()
            print("Insert successful")
            return True
        except mysql.connector.IntegrityError as e:
            print(f"Integrity error: {e}")
            return False
        except mysql.connector.Error as e:
            print(f"Database error: {e}")
            return False

    def close_connection(self):
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()


class Config:
    ALLOWED_EXTENSIONS = {'py'}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB limit
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-please-change-in-production'
    UPLOAD_FOLDER = 'uploads'


class VulnerabilityScanner:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def allowed_file(self, filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS
    
    def process_file(self, file):
        if not file or file.filename == '':
            return jsonify(status='error', error='No file selected'), 400
        
        if not self.allowed_file(file.filename):
            return jsonify(status='error', error='Invalid file type'), 400
        
        try:
            file_content = file.read()
            return self.run_security_scan(file_content)
        except Exception as e:
            self.logger.error(f'Error processing file: {str(e)}')
            return jsonify(status='error', error=str(e)), 500
    
    def run_security_scan(self, file_content):
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as temp_file:
                temp_file.write(file_content)
                temp_file_name = temp_file.name

            cmd = ["bandit", "-f", "json", temp_file_name]
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False
            )

            os.unlink(temp_file_name)

            if result.stdout:
                scan_data = json.loads(result.stdout)
                return jsonify(status='success', results=scan_data), 200
            
            if result.returncode == 0:
                return jsonify(status='success', results={'results': []}), 200
            
            return jsonify(status='error', error=result.stderr), 500

        except Exception as e:
            self.logger.error(f'Error running security scan: {str(e)}')
            return jsonify(status='error', error=str(e)), 500


# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize database and scanner
db = DatabaseManager()
scanner = VulnerabilityScanner()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.before_request
def before_request():
    if not hasattr(app, 'db_initialized'):
        app.db_initialized = db.initialize_connection()

@app.route('/')
def root():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if db.login_user(username, password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        return render_template('login.html', error="Invalid username or password")
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Validasi password
        password_regex = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        if not re.match(password_regex, password):
            return render_template(
                'register.html',
                error="Password harus memiliki minimal 8 karakter, termasuk huruf besar, huruf kecil, angka, dan simbol."
            )

        # Proses registrasi
        if db.register_user(username, email, password):
            return redirect(url_for('login', success="Registrasi berhasil! Silakan login."))
        
        return render_template('register.html', error="Registrasi gagal. Username atau email mungkin sudah terdaftar.")

    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/scan', methods=['POST'])
def scan():
    if 'username' not in session:
        return jsonify(status='error', error='Unauthorized'), 401
    
    if 'file' not in request.files:
        return jsonify(status='error', error='No file part'), 400
    
    return scanner.process_file(request.files['file'])

@app.teardown_appcontext
def teardown_db(exception):
    db.close_connection()

if __name__ == '__main__':
    try:
        subprocess.run(['bandit', '--version'], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.error("Bandit is not installed. Please install it using 'pip install bandit'")
        exit(1)
        
    app.run(debug=True)
