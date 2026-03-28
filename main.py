from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3

# Server configuration
hostName = "localhost"
serverPort = 8080
DB_FILE = "totally_not_my_privateKeys.db"

def init_db():
    """
    Initialize the SQLite database and create the 'keys' table if it doesn't exist.
    The table stores:
    - kid: Primary Key, Auto-incremented ID for each key.
    - key: BLOB, the serialized RSA private key in PEM format.
    - exp: INTEGER, the expiration timestamp (Unix time).
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def save_key_to_db(private_key, exp_timestamp):
    """
    Serialize an RSA private key into PKCS1 PEM format and save it to the database.
    This fulfills the requirement of persisting keys to disk.
    """
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (pem, exp_timestamp))
    conn.commit()
    conn.close()

def get_key_from_db(expired=False):
    """
    Retrieve a single private key from the database based on its expiration status.
    Uses parameterized SQL to prevent injection attacks.
    """
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    if expired:
        cursor.execute('SELECT key, kid FROM keys WHERE exp <= ? LIMIT 1', (now,))
    else:
        cursor.execute('SELECT key, kid FROM keys WHERE exp > ? LIMIT 1', (now,))
        
    row = cursor.fetchone()
    conn.close()
    return row

def get_all_valid_keys_from_db():
    """
    Retrieve all keys that have not yet expired from the database.
    Used for the JWKS endpoint.
    """
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT key, kid FROM keys WHERE exp > ?', (now,))
    rows = cursor.fetchall()
    conn.close()
    return rows

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
        Handles POST requests for /auth. Implements mock authentication 
        by extracting the username from Basic Auth or JSON payload.
        """
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/auth":
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

    webServer = HTTPServer((hostName, serverPort), MyServer)
    print(f"Server started http://{hostName}:{serverPort}")

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
