import os
import json
import subprocess
import logging
import tempfile
from flask import Flask, jsonify, render_template, request, send_from_directory, render_template, redirect, url_for, session
from werkzeug.utils import secure_filename
from io import BytesIO
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
import re

# Initialize Flask app
app = Flask(__name__, static_folder='static')

# Configuration
class Config:
    # Upload configuration
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

@app.route('/')
def root():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Koneksi ke database
        connection = get_db_connection()
        if connection is None:
            return render_template('login.html', error="Gagal terhubung ke database!")

        cursor = connection.cursor()
        
        try:
            # Query untuk mengambil data pengguna berdasarkan username
            cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
            result = cursor.fetchone()  # Ambil satu hasil (username yang cocok)
            
            if result:
                stored_password = result[0]
                # Memverifikasi password dengan hash yang ada di database
                if check_password_hash(stored_password, password):  # Gunakan check_password_hash
                    session['username'] = username
                    return redirect(url_for('dashboard'))
                else:
                    return render_template('login.html', error="Password salah!")
            else:
                return render_template('login.html', error="Username tidak ditemukan!")
        except Exception as e:
            return render_template('login.html', error=f"Terjadi kesalahan: {e}")
        finally:
            cursor.close()
            connection.close()

    return render_template('login.html')

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Validasi password
        password_regex = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        if not re.match(password_regex, password):
            return render_template(
                'register.html',
                error="Password harus memiliki minimal 8 karakter, termasuk huruf besar, huruf kecil, angka, dan simbol."
            )

        # Koneksi ke database
        connection = get_db_connection()
        if connection is None:
            return render_template(
                'register.html',
                error="Gagal terhubung ke database!"
            )

        cursor = connection.cursor()

        try:
            # Hash password sebelum menyimpan
            hashed_password = generate_password_hash(password)

            # Query untuk memasukkan data pengguna baru
            cursor.execute(
                "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                (username, email, hashed_password)
            )
            connection.commit()

            # Jika berhasil, arahkan ke form login dengan pesan sukses
            success_message = "Registrasi berhasil! Silakan login."
            return redirect(url_for('login', success=success_message))
        except mysql.connector.IntegrityError:
            # Jika username/email sudah terdaftar
            return render_template(
                'register.html',
                error="Username atau email sudah terdaftar!"
            )
        except Exception as e:
            return render_template(
                'register.html',
                error=f"Terjadi kesalahan: {e}"
            )
        finally:
            cursor.close()
            connection.close()

    # Render halaman register jika metode GET
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    print("Dashboard function called")
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
    # Verify Bandit is installed
    try:
        subprocess.run(['bandit', '--version'], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        logger.error("Bandit is not installed. Please install it using 'pip install bandit'")
        exit(1)
    except FileNotFoundError:
        logger.error("Bandit is not installed. Please install it using 'pip install bandit'")
        exit(1)
        
    app.run(debug=True)