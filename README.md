# JWKS Server

This repository contains a JWKS server built with Flask and SQLite for managing JWTs and keys.

## Setup

1. **Install Dependencies**:
   Make sure Python 3.x and pip are installed, then run:
   ```bash
   pip install Flask cryptography pyjwt

2. Setup SQLite:
    sqlite3 totally_not_my_privateKeys.db

3. Running the Serve
    python3 server.py
  #The server will run at http://127.0.0.1:8080.


  Endpoints

*Register a new user: curl -X POST http://127.0.0.1:8080/register -H "Content-Type: application/json" -d '{"username": "test_user", "email": "test@example.com"}'

*AUTHENTICATE: curl -X POST http://127.0.0.1:8080/auth


 GET /jwks

Example for valid key:
curl http://127.0.0.1:8080/jwks

Example for expired key:
curl -X POST "http://127.0.0.1:8080/auth?expired=true"

Testing
./gradebot project2
./gradebot project3


