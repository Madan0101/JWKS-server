from flask import Flask, request, jsonify
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat
import jwt
import time

app = Flask(__name__)

# Store keys
keys = []

def generate_key():
    """Generates an RSA key pair, assigns a unique kid and expiration, and stores it."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    exp_time = time.time() + 300      # Key expiring in 5 min
    kid = str(len(keys) + 1)          #unique key ID (kid)
    
    #private and public keys
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    
    # Appending the key info - keys list
    keys.append({
        "kid": kid,
        "private_key": private_pem,
        "public_key": public_pem,
        "exp": exp_time
    })
    
    print(f"Generated key with kid={kid}, exp={exp_time}")  
    return kid

@app.route('/jwks')
def jwks():
    """Provides the public keys that are still valid (not expired)."""
    # If no keys, create new one
    if not keys:
        generate_key()
    
    print("Current keys:", keys)

    valid_keys = {
        "keys": [
            {
                "kid": k["kid"],
                "exp": k["exp"],
                "public_key": k["public_key"].decode('utf-8')
            } for k in keys if k["exp"] > time.time()
        ]
    }
    return jsonify(valid_keys)

@app.route('/auth', methods=['POST'])
def auth():
    """Issues a JWT for valid requests; supports issuing with expired keys via query parameter."""
    expired = request.args.get('expired', 'false') == 'true'
    
    # Handling case where an expired JWT is requested
    if expired:
        expired_keys = [k for k in keys if k["exp"] < time.time()]
        if not expired_keys:
            return jsonify({"error": "No expired keys available"}), 400 
        key_info = expired_keys[-1]
    else:
        
        valid_keys = [k for k in keys if k["exp"] > time.time()]
        if not valid_keys:
            return jsonify({"error": "No valid keys available"}), 400 
        key_info = valid_keys[0]
    
    # Create JWT token
    token = jwt.encode(
        {
            "iss": "jwks_server",  
            "sub": "user@example.com",  
            "aud": "http://example.com",  
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5 if not expired else -5)  #expiration
        },
        key_info['private_key'],  
        algorithm="RS256",  
        headers={"kid": key_info["kid"]}  # Including the key ID (kid) in  JWT header
    )

    # Returning JWT token
    return jsonify({"token": token})

if __name__ == '__main__':
    print("Starting Flask app...")
    generate_key()  
    app.run(port=8080, debug=True)  # Starting the Flask server
