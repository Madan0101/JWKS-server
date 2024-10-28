import sqlite3
from flask import Flask, request, jsonify
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat
import jwt
import time

# Path to the SQLite database file
DB_FILE = 'totally_not_my_privateKeys.db'

def get_db_connection():
    """Connect to the SQLite database."""
    conn = sqlite3.connect(DB_FILE)
    return conn

def create_table():
    """Create the keys table if it doesn't exist."""
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

app = Flask(__name__)

def generate_key(expiration_offset=3600):
    """Generate an RSA key pair and store it in the database."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    exp_time = int(time.time()) + expiration_offset

    # Convert private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )

    # Store the private key and expiration in the database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (private_pem, exp_time))
    conn.commit()
    kid = cursor.lastrowid
    conn.close()

    return kid

@app.route('/jwks')
def jwks():
    """Return valid public keys as JWKs."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        current_time = int(time.time())

        # Fetch keys that have not expired
        cursor.execute('SELECT kid, key, exp FROM keys WHERE exp > ?', (current_time,))
        keys = cursor.fetchall()
        conn.close()

        # Prepare the response with valid keys
        valid_keys = {"keys": []}
        for row in keys:
            kid, private_key_pem, exp = row
            public_key = serialization.load_pem_private_key(private_key_pem, password=None).public_key()
            public_key_pem = public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

            valid_keys["keys"].append({
                "kid": str(kid),  # Ensure kid is a string
                "exp": exp,
                "public_key": public_key_pem
            })

        return jsonify(valid_keys)

    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

@app.route('/auth', methods=['POST'])
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

    # Load the private key and create a JWT token
    kid, private_key_pem = row
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
