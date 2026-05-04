from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3

import os
import uuid
import time
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# Server configuration
hostName = "localhost"
serverPort = 8080
DB_FILE = "totally_not_my_privateKeys.db"

# AES encryption key from environment variable
AES_KEY = os.environ.get("NOT_MY_KEY")

def get_aes_key():
    """Ensure the AES key is 32 bytes for AES-256."""
    if not AES_KEY:
        return b"default_32_byte_key_for_testing__"[:32]
    # Pad or truncate to 32 bytes if necessary, or just use as is if we assume it's correct
    key_bytes = AES_KEY.encode()
    if len(key_bytes) < 32:
        return key_bytes.ljust(32, b'\0')
    return key_bytes[:32]

def encrypt_key(data):
    """Encrypt data using AES-CBC with a random IV."""
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(get_aes_key()), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data, iv

def decrypt_key(encrypted_data, iv):
    """Decrypt data using AES-CBC with the provided IV."""
    cipher = Cipher(algorithms.AES(get_aes_key()), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

def init_db():
    """
    Initialize the SQLite database and create necessary tables.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # Keys table with IV column for AES
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            iv BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP      
        )
    ''')
    # Auth logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,  
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

def save_key_to_db(private_key, exp_timestamp):
    """
    Serialize an RSA private key, encrypt it, and save it to the database.
    """
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    encrypted_pem, iv = encrypt_key(pem)
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO keys (key, iv, exp) VALUES (?, ?, ?)', (encrypted_pem, iv, exp_timestamp))
    conn.commit()
    conn.close()

def get_key_from_db(expired=False):
    """
    Retrieve and decrypt a single private key from the database.
    """
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    if expired:
        cursor.execute('SELECT key, iv, kid FROM keys WHERE exp <= ? LIMIT 1', (now,))
    else:
        cursor.execute('SELECT key, iv, kid FROM keys WHERE exp > ? LIMIT 1', (now,))
        
    row = cursor.fetchone()
    conn.close()
    
    if row:
        encrypted_pem, iv, kid = row
        pem = decrypt_key(encrypted_pem, iv)
        return pem, kid
    return None

def get_all_valid_keys_from_db():
    """
    Retrieve and decrypt all valid keys from the database.
    """
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT key, iv, kid FROM keys WHERE exp > ?', (now,))
    rows = cursor.fetchall()
    conn.close()
    
    decrypted_keys = []
    for encrypted_pem, iv, kid in rows:
        pem = decrypt_key(encrypted_pem, iv)
        decrypted_keys.append((pem, kid))
    return decrypted_keys

class RateLimiter:
    """Simple rate limiter implementing a fixed-window approach."""
    def __init__(self, limit, window):
        self.limit = limit
        self.window = window
        self.requests = {} # IP -> [(timestamp, count)]

    def is_allowed(self, ip):
        now = time.time()
        if ip not in self.requests:
            self.requests[ip] = []
        
        # Filter requests within the current window
        self.requests[ip] = [t for t in self.requests[ip] if now - t < self.window]
        
        if len(self.requests[ip]) < self.limit:
            self.requests[ip].append(now)
            return True
        return False

rate_limiter = RateLimiter(10, 1) # 10 requests per second
ph = PasswordHasher()

def int_to_base64(value):
    """
    Convert a large integer (RSA component) into a Base64URL-encoded string.
    """
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
    """
    HTTP Server handler implementing the JWKS and Auth endpoints.
    """
    
    def do_PUT(self): self.send_response(405); self.end_headers()
    def do_PATCH(self): self.send_response(405); self.end_headers()
    def do_DELETE(self): self.send_response(405); self.end_headers()
    def do_HEAD(self): self.send_response(405); self.end_headers()

    def do_POST(self):
        """
        Handles POST requests for /auth and /register.
        """
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == "/register":
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                try:
                    body = self.rfile.read(content_length).decode('utf-8')
                    json_data = json.loads(body)
                    username = json_data.get('username')
                    email = json_data.get('email')
                    
                    if not username:
                        self.send_response(400)
                        self.end_headers()
                        return

                    # Generate UUIDv4 password
                    password = str(uuid.uuid4())
                    password_hash = ph.hash(password)
                    
                    conn = sqlite3.connect(DB_FILE)
                    cursor = conn.cursor()
                    try:
                        cursor.execute('INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)', 
                                       (username, password_hash, email))
                        conn.commit()
                        self.send_response(201)
                        self.send_header("Content-type", "application/json")
                        self.end_headers()
                        self.wfile.write(bytes(json.dumps({"password": password}), "utf-8"))
                    except sqlite3.IntegrityError:
                        self.send_response(400)
                        self.end_headers()
                        self.wfile.write(b"User already exists")
                    finally:
                        conn.close()
                    return
                except Exception as e:
                    self.send_response(400)
                    self.end_headers()
                    return

        if parsed_path.path == "/auth":
            # Rate Limiting
            client_ip = self.client_address[0]
            if not rate_limiter.is_allowed(client_ip):
                self.send_response(429)
                self.end_headers()
                self.wfile.write(b"Too Many Requests")
                return

            username = "sampleUser" # Default username
            
            # 1. Attempt to extract username from Basic Auth header
            auth_header = self.headers.get('Authorization')
            if auth_header and auth_header.startswith('Basic '):
                try:
                    encoded_creds = auth_header.split(' ')[1]
                    decoded_creds = base64.b64decode(encoded_creds).decode('utf-8')
                    username = decoded_creds.split(':')[0]
                except Exception:
                    pass
            
            # 2. Attempt to extract username from JSON payload
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                try:
                    body = self.rfile.read(content_length).decode('utf-8')
                    json_data = json.loads(body)
                    if 'username' in json_data:
                        username = json_data['username']
                except Exception:
                    pass

            # Log Authentication Request
            user_id = None
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            if row:
                user_id = row[0]
            
            cursor.execute('INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)', (client_ip, user_id))
            conn.commit()
            conn.close()

            # Handle the 'expired' query parameter
            params = parse_qs(parsed_path.query)
            expired = 'expired' in params

            # Retrieve the appropriate private key from SQLite
            row = get_key_from_db(expired=expired)
            if not row:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"No suitable key found in database")
                return

            private_key_pem, kid = row
            
            # Create JWT payload for the identified user
            now = datetime.datetime.now(datetime.timezone.utc)
            token_payload = {
                "user": username,
                "iat": int(now.timestamp()),
                "exp": int((now + datetime.timedelta(hours=1)).timestamp())
            }
            if expired:
                token_payload["exp"] = int((now - datetime.timedelta(hours=1)).timestamp())

            # Sign the JWT and include the KID in the header
            headers = {"kid": str(kid)}
            encoded_jwt = jwt.encode(token_payload, private_key_pem, algorithm="RS256", headers=headers)
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        """
        Handles GET requests for the JWKS endpoint.
        """
        if self.path == "/.well-known/jwks.json":
            rows = get_all_valid_keys_from_db()
            keys = []
            
            for pem, kid in rows:
                private_key = serialization.load_pem_private_key(pem, password=None)
                numbers = private_key.private_numbers()
                
                keys.append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),
                    "n": int_to_base64(numbers.public_numbers.n),
                    "e": int_to_base64(numbers.public_numbers.e),
                })
            
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps({"keys": keys}), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()

if __name__ == "__main__":
    init_db()

    # Generate and store a valid key (expires in 1 hour)
    good_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    good_exp = int((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).timestamp())
    save_key_to_db(good_key, good_exp)

    # Generate and store an expired key (expired 1 hour ago)
    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired_exp = int((datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).timestamp())
    save_key_to_db(expired_key, expired_exp)

    webServer = ThreadingHTTPServer((hostName, serverPort), MyServer)
    print(f"Server started http://{hostName}:{serverPort}")

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
