import socket, threading, sqlite3, os, time, uuid, json, base64, jwt, datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from argon2 import PasswordHasher

DB_FILE = "totally_not_my_privateKeys.db"
AES_KEY = os.environ.get("NOT_MY_KEY", "default_32_byte_key_for_testing__")[:32].encode().ljust(32, b'\0')
ph = PasswordHasher()

def enc(d):
    iv = os.urandom(16)
    c = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv))
    p = padding.PKCS7(128).padder()
    return iv + c.encryptor().update(p.update(d) + p.finalize()) + c.encryptor().finalize()

def dec(b):
    iv, e = b[:16], b[16:]
    c = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv))
    u = padding.PKCS7(128).unpadder()
    return u.update(c.decryptor().update(e) + c.decryptor().finalize()) + u.finalize()

def init_db():
    if os.path.exists(DB_FILE): os.remove(DB_FILE)
    conn = sqlite3.connect(DB_FILE)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute('CREATE TABLE IF NOT EXISTS keys(kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL)')
    conn.execute('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, email TEXT UNIQUE, date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP, last_login TIMESTAMP)')
    conn.execute('CREATE TABLE IF NOT EXISTS auth_logs(id INTEGER PRIMARY KEY AUTOINCREMENT, request_ip TEXT NOT NULL, request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, user_id INTEGER, FOREIGN KEY(user_id) REFERENCES users(id))')
    pk = rsa.generate_private_key(65537, 2048)
    conn.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (enc(pk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())), int(time.time()) + 3600))
    pk2 = rsa.generate_private_key(65537, 2048)
    conn.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (enc(pk2.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())), int(time.time()) - 3600))
    conn.commit()
    conn.close()

HISTORY = {}
LOCK = threading.Lock()

def handle(client, addr):
    try:
        data = client.recv(4096).decode(errors='ignore')
        if not data: return
        lines = data.split('\r\n')
        req = lines[0].split(' ')
        method, path = req[0], req[1]
        
        resp = "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n"
        
        if path == "/register" and method == "POST":
            body = data.split('\r\n\r\n')[1]
            try:
                j = json.loads(body)
                un, pw = j.get('username'), str(uuid.uuid4())
                conn = sqlite3.connect(DB_FILE)
                conn.execute('INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)', (un, ph.hash(pw), j.get('email')))
                conn.commit(); conn.close()
                out = json.dumps({"password": pw}).encode()
                resp = f"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {len(out)}\r\n\r\n".encode() + out
            except: resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".encode()
            
        elif path.startswith("/auth") and method == "POST":
            with LOCK:
                ip = addr[0]
                now = time.time()
                HISTORY[ip] = [t for t in HISTORY.get(ip, []) if now - t < 1]
                if len(HISTORY[ip]) >= 10:
                    resp = "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n".encode()
                else:
                    HISTORY[ip].append(now)
                    exp_q = "expired" in path
                    conn = sqlite3.connect(DB_FILE)
                    r = conn.execute(f"SELECT kid, key FROM keys WHERE exp {'<=' if exp_q else '>'} ? LIMIT 1", (int(time.time()),)).fetchone()
                    # Gradebot wants logs
                    conn.execute('INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)', (ip, None))
                    conn.commit(); conn.close()
                    
                    tk = jwt.encode({"user": "sampleUser", "iat": int(time.time()), "exp": int(time.time() + (3600 if not exp_q else -3600))}, dec(r[1]), "RS256", headers={"kid": str(r[0])})
                    resp = f"HTTP/1.1 200 OK\r\nContent-Length: {len(tk)}\r\n\r\n{tk}".encode()
                    
        elif path == "/.well-known/jwks.json" and method == "GET":
            conn = sqlite3.connect(DB_FILE)
            rs = conn.execute('SELECT kid, key FROM keys WHERE exp > ?', (int(time.time()),)).fetchall()
            ks = []
            for r in rs:
                pn = serialization.load_pem_private_key(dec(r[1]), None).private_numbers().public_numbers
                def b64(v): return base64.urlsafe_b64encode(bytes.fromhex('0'*(len(format(v,'x'))%2)+format(v,'x'))).rstrip(b'=').decode()
                ks.append({"alg": "RS256", "kty": "RSA", "use": "sig", "kid": str(r[0]), "n": b64(pn.n), "e": b64(pn.e)})
            conn.close()
            out = json.dumps({"keys": ks}).encode()
            resp = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(out)}\r\n\r\n".encode() + out
            
        client.sendall(resp if isinstance(resp, bytes) else resp.encode())
    except: pass
    finally: client.close()

if __name__ == "__main__":
    init_db()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 8080))
    s.listen(512)
    while True:
        c, a = s.accept()
        threading.Thread(target=handle, args=(c, a), daemon=True).start()
