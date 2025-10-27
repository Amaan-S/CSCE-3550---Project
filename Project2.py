'''
Name: Amaan Jamil Siddiqui
euid: ajs0576
Section: CSCE 3550.001
'''


from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime as dt
import time as t


#import needed for sqlite
import sqlite3


#token used for the tests:
def Token(kid: int, pem_bytes: bytes) -> dict:
    priv = Encode_PEM_format_key(pem_bytes)
    pub = priv.public_key().public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": str(kid),
        "n": jwt.b64u_int(pub.n),
        "e": jwt.b64u_int(pub.e),
    }

#function used to setup sqlite database
def SQLITE_start(): 
    #sqlite initializations needed for the database.
    connection = sqlite3.connect('totally_not_my_privateKeys.db')     #FakeKeys.db is the name of the file for database
    
    #insert the provided table into the created database connection file
    connection.execute(
        '''
        CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
    )
        '''
    )
    
    connection.commit()
    connection.close()
    
#funciton to close the conneciton to the sqlite database
def SQLITE_close():
    
    #get the connection to the database
    connection = sqlite3.connect('totally_not_my_privateKeys.db')
    
    #close the database connection so that it isn't left open accidentally
    connection.close()

#function to insert the private key into the database
def SQLITE_KEY_INSERT(P_Key, Exp_time: int):
    
    #make connection to db again
    connection = sqlite3.connect('totally_not_my_privateKeys.db')
    
    #insert the desired value into the db table
    connection.execute(f"INSERT INTO ")
    
    
def SQLITE_getAkey():
    
    #make connection to db again
    connection = sqlite3.connect('totally_not_my_privateKeys.db')  


hostName = "localhost"
serverPort = 8080



private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

#reuse the declaration private_key to do this and generate private keys (so more than one can be created)
def Gen_P_key():
    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    )
    
    #return the new generated key
    return private_key


#Encode generated priv
def Encode_PEM_format_key(key_val) -> bytes:
    return key_val.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # PKCS#1
        encryption_algorithm=serialization.NoEncryption()
    )
    
    
#decodes the encrypted PEM converted key    
def Decode_PEM_format_key(E_key_val: bytes):
    return serialization.load_pem_private_key(E_key_val, password=None)
    
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

numbers = private_key.private_numbers()

#functions relating to getting keys out of the database and inserting keys into it

#insert private key into the database
def Insert(P_key, E_time: int) -> int:
    
    #encode the private key to PEM format
    Encrypted_key = Encode_PEM_format_key(P_key)
    
    #make connection to db again
    connection = sqlite3.connect('totally_not_my_privateKeys.db')
    
    #insert the values into the database
    Insert_command = connection.execute("INSERT INTO keys(key, exp) VALUES(?, ?)", (Encrypted_key, E_time))
    
    connection.commit()
    connection.close()
    
    return Insert_command.lastrowid  # kid value from the keys table


#function to get a singular key that isn't expired from the database
def pick_A_valid_key (expired: bool):
    
    #get the current time
    now = int(t.time())
    
    #query to find the first unexpired key, but if the key is expired look at the table in reverse so you get the most recently issued key to the db table
    query = """
        SELECT kid, key, exp FROM keys
        WHERE exp <= ? ORDER BY exp DESC LIMIT 1
    """ if expired else """
        SELECT kid, key, exp FROM keys
        WHERE exp > ? ORDER BY exp ASC LIMIT 1
    """
    connection = connection = sqlite3.connect('totally_not_my_privateKeys.db')
    connection.row_factory = sqlite3.Row
    row = connection.execute(query, (now,)).fetchone()
    connection.close()
    
    #if a key is found, return the entries of the matching row to the 
    return row

#funciton to get every valid key from the database
def Find_SPIT_ALL_keys_DB():
    
    #get the current time
    now = int(t.time())
    
    connection =  sqlite3.connect('totally_not_my_privateKeys.db')
    connection.row_factory = sqlite3.Row
    #return every key stoted in the sqlite db keys table
    rows =  connection.execute("SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp", (now,)).fetchall()

    connection.close()
    
    return rows

#Populate an expired and unexpired key to the table to ensure values are there
def seed_keys_db():
    #create a bad key
    if pick_A_valid_key(expired = True) is None:
        new_key = Gen_P_key()
        Insert(new_key,int(t.time()) - 10)
    
    #create a good key
    if pick_A_valid_key(expired = False) is None:
        new_key = Gen_P_key()
        Insert(new_key,int(t.time()) + 3600)        #key is valid for an hour

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return


# new post request
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": dt.datetime.utcnow() + dt.timedelta(hours=1)
            }


        # NEW: decide which kind of key we want based on the query param (keeps your old logic)
        want_expired = 'expired' in params

        # NEW: fetch one matching key from SQLite (expects helper get_one_key(expired: bool))
        row = pick_A_valid_key(expired=want_expired)
        if not row:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"No matching key was found in the keys table of the DB")
            return

        # usethe DB kid and PEM to post the key to the table
        headers["kid"] = str(row["kid"])
        pem_bytes = row["key"]  # stored as PEM in BLOB/TEXT

        # build payload to send out
        if want_expired:
            headers["kid"] = str(row["kid"])  # keep (re-)assignment minimal
            token_payload["exp"] = dt.datetime.utcnow() - dt.timedelta(hours=1)
            
            encoded_jwt = jwt.encode(token_payload, pem_bytes, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        encoded_jwt = jwt.encode(token_payload, pem_bytes, algorithm="RS256", headers=headers)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(bytes(encoded_jwt, "utf-8"))
        return

        self.send_response(405)
        self.end_headers()
        return


#get request
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            
            #different from project1, because now JWKS is being made for all unexpired keys in database
            JWK_List = []
            
            rows = Find_SPIT_ALL_keys_DB()           #call created funciton to get keys
            
            for row in rows:
                priv = Decode_PEM_format_key(row["key"])
                pub_numbers = priv.public_key().public_numbers()
                
                try:
                    #get a private key value from the database
                    JWK_List.append({
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": str(row["kid"]),
                        "n": int_to_base64(pub_numbers.n),
                        "e": int_to_base64(pub_numbers.e),
                    })
                    
                except Exception:
                    continue        #just proceed with the request further if unreadable
                    
            #SET KEYS TO THE CREATED JWT_LIST WITH THE DATABASE INFORMATION
            keys = {"keys": JWK_List}
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        #start the sqlite database and insert some keys into it (one valid and one invalid)
        SQLITE_start()
        seed_keys_db()
        
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
