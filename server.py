import sqlite3
from flask import Flask, request, jsonify
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import jwt
import time
import os
import hashlib
from werkzeug.security import generate_password_hash
import uuid
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging

# Flask app initialization
app = Flask(__name__)

DB_FILE = 'totally_not_my_privateKeys.db'  # SQLite database file
# AES key initialization (Make sure the environment variable is set)
AES_KEY = os.getenv('NOT_MY_KEY').encode()

if AES_KEY is None:
    raise ValueError("The environment variable 'NOT_MY_KEY' is not set.")

AES_KEY = AES_KEY.ljust(32, b'\0')[:32]  # Encoding AES key

# Initialize limiter after app
limiter = Limiter(app)

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# AES Encryption and Decryption functions
def encrypt_private_key(private_key_pem):
    """Encrypt the private key using AES."""
    # Pad the private key to be a multiple of the block size (16 bytes)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(private_key_pem) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_KEY[:16]), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_key = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_key

def decrypt_private_key(encrypted_private_key):
    """Decrypt the private key using AES."""
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_KEY[:16]), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_private_key) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    private_key_pem = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    
    return private_key_pem

def get_db_connection():
    """Connect to the SQLite database."""
    conn = sqlite3.connect(DB_FILE)
    conn.execute('PRAGMA journal_mode=WAL;')  # Enable Write-Ahead Logging (WAL)
    return conn

def create_table():
    """Create necessary tables in the database if they don't exist."""
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP      
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS auth_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

def generate_key(expiration_offset=3600):
    """Generate an RSA key pair, encrypt it, and store it in the database."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    exp_time = int(time.time()) + expiration_offset

    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )

    # Encrypt the private key
    encrypted_private_key = encrypt_private_key(private_pem)

    # Store the encrypted private key in the database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (encrypted_private_key, exp_time))
    conn.commit()
    kid = cursor.lastrowid
    conn.close()

    return kid

@app.route('/register', methods=['POST'])
def register():
    """Handle user registration."""
    try:
        data = request.get_json()
        username = data['username']
        email = data['email']
        password = str(uuid.uuid4())  # Generate a secure UUIDv4 password
        password_hash = generate_password_hash(password, method='argon2')

        # Log the incoming request data (for debugging purposes)
        logging.info(f"Registering user: {username}, {email}")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', 
                       (username, email, password_hash))
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()

        logging.info(f"User registered successfully: {username}, {email}")
        
        return jsonify({"password": password}), 201
    except Exception as e:
        logging.error(f"Error during registration: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route('/auth', methods=['POST'])
@limiter.limit("10 per second")  # Rate Limiting: 10 requests per second
def auth():
    """Issue a JWT for valid requests; support expired keys via query parameter."""
    expired = request.args.get('expired', 'false') == 'true'
    conn = get_db_connection()
    cursor = conn.cursor()
    current_time = int(time.time())

    # Select key based on whether it is expired
    if expired:
        cursor.execute('SELECT kid, key FROM keys WHERE exp < ? ORDER BY exp DESC LIMIT 1', (current_time,))
    else:
        cursor.execute('SELECT kid, key FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1', (current_time,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "No valid or expired keys available"}), 400

    # Log the authentication request
    ip = request.remote_addr
    user_id = None  # You would have to implement logic to fetch user ID based on username
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)', (ip, user_id))
    conn.commit()
    conn.close()

    # Load the private key and create a JWT token
    kid, encrypted_key = row
    private_key_pem = decrypt_private_key(encrypted_key)
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    token = jwt.encode(
        {
            "iss": "jwks_server",
            "sub": "user@example.com",
            "aud": "http://example.com",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5 if not expired else -5)
        },
        private_key,
        algorithm="RS256",
        headers={"kid": str(kid)}  # Include kid in JWT header as a string
    )

    return jsonify({"token": token})

if __name__ == '__main__':
    conn = get_db_connection()
    print("Database connected successfully")
    conn.close()

    create_table()

    # Generate a valid key and an expired key for testing
    generate_key()
    generate_key(-1000)

    print("Starting Flask app...")
    app.run(port=8080)
