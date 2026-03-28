import pytest
import requests
import threading
import time
import sqlite3
import os
import json
import jwt
import sys
from datetime import datetime, timedelta, timezone

# Add the py3 directory to sys.path so we can import main
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from main import HTTPServer, MyServer, DB_FILE, init_db, save_key_to_db, rsa

# Configuration for the test server
TEST_HOST = "localhost"
TEST_PORT = 8081
TEST_URL = f"http://{TEST_HOST}:{TEST_PORT}"

@pytest.fixture(scope="module", autouse=True)
def test_server():
    # Remove existing test DB if any
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    
    init_db()
    
    # Generate and store keys
    good_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    good_exp = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
    save_key_to_db(good_key, good_exp)

    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired_exp = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
    save_key_to_db(expired_key, expired_exp)

    server = HTTPServer((TEST_HOST, TEST_PORT), MyServer)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    
    # Give the server a moment to start
    time.sleep(1)
    
    yield server
    
    server.shutdown()
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)

def test_jwks_endpoint():
    response = requests.get(f"{TEST_URL}/.well-known/jwks.json")
    assert response.status_code == 200
    data = response.json()
    assert "keys" in data
    # Should only have the non-expired key
    assert len(data["keys"]) == 1
    assert data["keys"][0]["alg"] == "RS256"

def test_auth_endpoint_valid():
    response = requests.post(f"{TEST_URL}/auth")
    assert response.status_code == 200
    token = response.text
    # Verify JWT
    decoded = jwt.decode(token, options={"verify_signature": False})
    assert decoded["exp"] > int(datetime.now(timezone.utc).timestamp())

def test_auth_endpoint_expired():
    response = requests.post(f"{TEST_URL}/auth?expired=true")
    assert response.status_code == 200
    token = response.text
    # Verify JWT is expired
    decoded = jwt.decode(token, options={"verify_signature": False})
    assert decoded["exp"] < int(datetime.now(timezone.utc).timestamp())

def test_auth_with_basic_auth():
    response = requests.post(f"{TEST_URL}/auth", auth=("userABC", "password123"))
    assert response.status_code == 200

def test_auth_with_json_payload():
    payload = {"username": "userABC", "password": "password123"}
    response = requests.post(f"{TEST_URL}/auth", json=payload)
    assert response.status_code == 200

def test_unsupported_methods():
    for method in [requests.put, requests.patch, requests.delete]:
        response = method(f"{TEST_URL}/auth")
        assert response.status_code == 405
        response = method(f"{TEST_URL}/.well-known/jwks.json")
        assert response.status_code == 405

def test_invalid_path():
    response = requests.get(f"{TEST_URL}/invalid")
    assert response.status_code == 405
