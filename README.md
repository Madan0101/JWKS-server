* JWKS Server

* Introduction
This project creates a simple server that generates and shares public keys used to verify JWTs (JSON Web Tokens). It can issue both valid and expired JWTs.

* How to Run

1. **Clone the project**:
   ```bash
   git clone https://github.com/Madan0101/JWKS-server.git
   cd JWKS-server

2. Install requirements: pip install -r requirements.txt
3. Start server: python server.py
The server will run on http://127.0.0.1:8080

* Endpoints

   * Get public keys:
    curl http://127.0.0.1:8080/jwks

   * Get a valid JWT:
    curl -X POST http://127.0.0.1:8080/auth

    * Get an expired JWT:
    curl -X POST "http://127.0.0.1:8080/auth?expired=true"

* Testing:
Use curl as above or tools like Postman to test the server.


*** Run the tests using pytest: pytest
