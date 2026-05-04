import pytest
import requests
import threading
import time
import os
import json
import sqlite3
import jwt
from datetime import datetime, timedelta, timezone

# Import server details
from main import HTTPServer, ThreadingHTTPServer, MyServer, DB_FILE, init_db

# Configuration for the test server
TEST_HOST = "localhost"
TEST_PORT = 8082
TEST_URL = f"http://{TEST_HOST}:{TEST_PORT}"

@pytest.fixture(scope="module", autouse=True)
def test_server():
    # Set environment variable for AES key
    os.environ["NOT_MY_KEY"] = "this_is_a_very_secret_key_32_bytes"

    # Remove existing test DB if any
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    
    init_db()
    
    # Manually generate and store keys since main's block doesn't run on import
    from main import rsa, save_key_to_db
    good_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    good_exp = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
    save_key_to_db(good_key, good_exp)

    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired_exp = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
    save_key_to_db(expired_key, expired_exp)
    
    server = ThreadingHTTPServer((TEST_HOST, TEST_PORT), MyServer)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    
    # Give the server a moment to start
    time.sleep(1)
    
    yield server
    
    server.shutdown()
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)

def test_register_endpoint():
    payload = {"username": "testuser", "email": "test@example.com"}
    response = requests.post(f"{TEST_URL}/register", json=payload)
    assert response.status_code in [200, 201]
    data = response.json()
    assert "password" in data
    # Password should be a UUID
    assert len(data["password"]) == 36

def test_register_duplicate_user():
    payload = {"username": "duplicate", "email": "dup@example.com"}
    response = requests.post(f"{TEST_URL}/register", json=payload)
    assert response.status_code in [200, 201]
    
    response = requests.post(f"{TEST_URL}/register", json=payload)
    assert response.status_code == 400

def test_auth_logging():
    # First register a user
    username = "loguser"
    requests.post(f"{TEST_URL}/register", json={"username": username, "email": "log@example.com"})
    
    # Perform auth
    requests.post(f"{TEST_URL}/auth", json={"username": username})
    
    # Check DB for logs
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT u.username FROM auth_logs al JOIN users u ON al.user_id = u.id WHERE u.username = ?', (username,))
    row = cursor.fetchone()
    conn.close()
    
    assert row is not None
    assert row[0] == username

def test_rate_limiting():
    # We should be able to make 10 requests, the 11th should fail
    # We send them in parallel to ensure they fall within the 1s window.
    time.sleep(1.1)
    
    results = []
    def make_request():
        try:
            r = requests.post(f"{TEST_URL}/auth")
            results.append(r.status_code)
        except:
            pass

    threads = []
    for i in range(25):
        t = threading.Thread(target=make_request)
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    # At least one should be 429
    assert 429 in results
    assert 200 in results

def test_aes_encryption_in_db():
    # Insert a key (the main block of main.py doesn't run when imported, 
    # so we need to manually add keys or run the script)
    # Wait, the MyServer expects keys to be there. 
    # Let's manually add a key using the functions from main.
    from main import rsa, save_key_to_db, get_key_from_db
    
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    exp = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
    save_key_to_db(key, exp)
    
    # Verify it's encrypted in DB (blob should not be raw PEM)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT key, iv FROM keys ORDER BY kid DESC LIMIT 1')
    encrypted_key, iv = cursor.fetchone()
    conn.close()
    
    # Try to decrypt it manually to see if it works
    from main import decrypt_key
    decrypted_pem = decrypt_key(encrypted_key, iv)
    assert b"BEGIN RSA PRIVATE KEY" in decrypted_pem
