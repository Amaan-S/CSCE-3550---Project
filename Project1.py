# ----------------------------
# Name: Amaan Jamil Siddiqui
# euid: ajs0576
# ----------------------------



#importing all necessary library dependencies for the JWKS server


import base64, json, sys, threading, datetime as dt, jwt

from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingMixIn, TCPServer
from urllib.parse import urlparse, parse_qs
from dataclasses import dataclass
from uuid import uuid4
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# ----------------------------
# RSA Key and JWT Handling portion of server
# ----------------------------


# ----------------------------
# Function used to base64 encode/decode keys
# ----------------------------
def b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


# ----------------------------
# Key records & in-memory store
# ----------------------------
@dataclass(frozen=True)
class KeyRecord:
    kid: str
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey
    expires_at: dt.datetime  # timezone-aware UTC

# ----------------------------
# Function to generate a private rsa key and then derive a public rsa key from the generated private key
# ----------------------------
def generate_rsa_key(expires_at: dt.datetime) -> KeyRecord:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    return KeyRecord(kid=str(uuid4()), private_key=priv, public_key=pub, expires_at=expires_at)



# ----------------------------
# Function that produces a json web jey from the public rsa_key that was generated
# ----------------------------
def jwk_from_public(key: KeyRecord) -> dict:
    nums = key.public_key.public_numbers()
    n_bytes = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
    e_bytes = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
    return {
        "kty": "RSA",
        "kid": key.kid,
        "use": "sig",
        "alg": "RS256",
        "n": b64url_nopad(n_bytes),
        "e": b64url_nopad(e_bytes),
    }



# ----------------------------
# Class that holds the private and public rsa key information
# ----------------------------
class KeyStore:

    def __init__(self) -> None:
        now = dt.datetime.now(dt.timezone.utc)
        self._expired = generate_rsa_key(now - dt.timedelta(days=1))   # for expired tokens
        self._current = generate_rsa_key(now + dt.timedelta(days=30))  # for valid tokens

    def current(self) -> KeyRecord:     #this is the key that is unexpired and is what appears in the JWKS
        return self._current

    def expired(self) -> KeyRecord:     #this is the key that is EXPIRED and is what NEVER shows up in the JWKS
        return self._expired

    def jwks(self) -> dict:     #This function will only return keys that are valid (unexpired)
        now = dt.datetime.now(dt.timezone.utc)
        keys = []
        if self._current.expires_at > now:
            keys.append(jwk_from_public(self._current))
        return {"keys": keys}


# ----------------------------
# private_pem and mint_jwt are used to create the JSON Web Tokens
# ----------------------------
def private_pem(priv: rsa.RSAPrivateKey) -> bytes:
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def mint_jwt(priv_pem: bytes, kid: str, *, expired: bool = False) -> str:       #
    now = dt.datetime.now(dt.timezone.utc)
    exp = now - dt.timedelta(minutes=5) if expired else now + dt.timedelta(minutes=10)

    headers = {"alg": "RS256", "kid": kid, "typ": "JWT"}
    claims = {
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(claims, priv_pem, algorithm="RS256", headers=headers)


# ----------------------------
# HTTP Handling Section of Server
# ----------------------------
ALLOWED_JWKS = "GET, HEAD"
ALLOWED_AUTH = "POST"


class JWKSHandler(BaseHTTPRequestHandler):      #Class handles HTTP requests and takes returns the appropriate headers given a GET, HEAD, OR POST request
    protocol_version = "HTTP/1.1"
    keystore: KeyStore | None = None  # set from bootstrap

    # Helpers
    def _send_json(self, status: int, payload: dict) -> None:           #function formulates and returns a built HTTP response
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _405(self, allow: str) -> None:     #function returns response for an invalid response (it isnt a GET, HEAD, or POST request)
        self.send_response(405)
        self.send_header("Allow", "GET, HEAD" if self.path.endswith("jwks.json") else "POST")
        self.send_header("Content-Length", "0")
        self.end_headers()

    # Routes
    def do_GET(self) -> None:           #function returns a response without the keys
        parsed = urlparse(self.path)
        if parsed.path == "/.well-known/jwks.json":
            self._send_json(200, self.keystore.jwks())  # type: ignore[arg-type]
        else:
            self.send_error(404)

    def do_HEAD(self) -> None:          #function returns a response without the keys
        parsed = urlparse(self.path)
        if parsed.path == "/.well-known/jwks.json":
            self._send_json(200, self.keystore.jwks())  # type: ignore[arg-type]
        else:
            self.send_error(404)

    def do_POST(self) -> None:          #Funtion returns a response with keys since it is POST request
        parsed = urlparse(self.path)
        if parsed.path == "/auth":
            qs = parse_qs(parsed.query)
            expired_flag = qs.get("expired", ["false"])[0].lower() in ("1", "true", "yes")
            key = (self.keystore.expired() if expired_flag else self.keystore.current())  # type: ignore[union-attr]
            token = mint_jwt(private_pem(key.private_key), key.kid, expired=expired_flag)
            self._send_json(200, {"token": token})
        elif parsed.path == "/.well-known/jwks.json":
            self._405(ALLOWED_JWKS)
        else:
            self.send_error(404)
            
    # Functions to handle behavior of a request with an invalid type
    def do_PUT(self) -> None:
        self._guard_methods()

    def do_PATCH(self) -> None:
        self._guard_methods()

    def do_DELETE(self) -> None:
        self._guard_methods()

    def _guard_methods(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/.well-known/jwks.json":
            self._405(ALLOWED_JWKS)
        elif parsed.path == "/auth":
            self._405(ALLOWED_AUTH)
        else:
            self.send_error(404)


class ThreadingHTTPServer(ThreadingMixIn, TCPServer):       #Function to facilitate recurring connection to server
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    # Build in-memory keystore (one current + one expired)
    store = KeyStore()
    JWKSHandler.keystore = store  # inject for handler

    server = ThreadingHTTPServer(("127.0.0.1", 8080), JWKSHandler)          #function that assigns the host IP address and port of use to the server

    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()                                                               #function that opens the socket/starts the server
    print("Serving http://127.0.0.1:8080  (press Enter to stop)")

    try:
        sys.stdin.readline()  # press Enter to stop
    finally:
        print("Shutting down...")
        server.shutdown()
        t.join(timeout=2)
        server.server_close()


if __name__ == "__main__":
    main()

