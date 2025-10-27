# test_main.py
import os
import sys
import json
import time
import threading
import http.client
import sqlite3
import jwt
import datetime as dt
import socket

import pytest


@pytest.fixture(scope="session")
def app_module():
    """
    Import the student's app as a module named 'main'.
    Assumes main.py is in the same directory as this test file.
    """
    # Ensure we can import 'main'
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    import main as app
    return app


@pytest.fixture
def tmp_workdir(tmp_path, monkeypatch, app_module):
    """
    Run each test in an isolated temp working directory so the
    DB file 'totally_not_my_privateKeys.db' is created there.
    """
    monkeypatch.chdir(tmp_path)
    yield tmp_path


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class ServerHandle:
    def __init__(self, httpd, thread, base_url, port):
        self.httpd = httpd
        self.thread = thread
        self.base_url = base_url
        self.port = port


def _start_server(app_module) -> ServerHandle:
    """
    Start HTTP server with a free port and return a handle.
    """
    port = _free_port()
    httpd = app_module.HTTPServer(("127.0.0.1", port), app_module.MyServer)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    base_url = f"http://127.0.0.1:{port}"
    return ServerHandle(httpd, t, base_url, port)


def _stop_server(handle: ServerHandle):
    handle.httpd.shutdown()
    handle.httpd.server_close()
    handle.thread.join(timeout=2)


def _http_request(port: int, method: str, path: str, body: bytes | None = None, headers: dict | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, resp.getheaders(), data
    finally:
        conn.close()


def _db_rows(db_path: str, sql: str, params=()):
    con = sqlite3.connect(db_path)
    try:
        return list(con.execute(sql, params))
    finally:
        con.close()


@pytest.fixture
def server(app_module, tmp_workdir):
    """
    Server with seeded DB (one expired, one valid).
    """
    # Create table and seed
    app_module.SQLITE_start()
    app_module.seed_keys_db()

    handle = _start_server(app_module)
    try:
        yield handle
    finally:
        _stop_server(handle)


@pytest.fixture
def server_empty(app_module, tmp_workdir):
    """
    Server with empty DB (no keys) to exercise 500 path in /auth.
    """
    app_module.SQLITE_start()
    # Ensure table is empty
    con = sqlite3.connect("totally_not_my_privateKeys.db")
    try:
        con.execute("DELETE FROM keys")
        con.commit()
    finally:
        con.close()

    handle = _start_server(app_module)
    try:
        yield handle
    finally:
        _stop_server(handle)


def test_database_created_and_seeded(app_module, tmp_workdir):
    app_module.SQLITE_start()
    app_module.seed_keys_db()

    # DB file must exist with the exact required name
    assert os.path.exists("totally_not_my_privateKeys.db")

    now = int(time.time())

    rows_all = _db_rows(
        "totally_not_my_privateKeys.db",
        "SELECT kid, key, exp FROM keys ORDER BY kid"
    )
    assert len(rows_all) >= 2  # at least one expired, one valid

    rows_expired = _db_rows(
        "totally_not_my_privateKeys.db",
        "SELECT COUNT(*) FROM keys WHERE exp <= ?",
        (now,)
    )
    rows_valid = _db_rows(
        "totally_not_my_privateKeys.db",
        "SELECT COUNT(*) FROM keys WHERE exp > ?",
        (now,)
    )
    assert rows_expired[0][0] >= 1
    assert rows_valid[0][0] >= 1


def test_auth_valid_token_and_header_kid_matches_db(app_module, server):
    status, headers, data = _http_request(server.port, "POST", "/auth")
    assert status == 200
    token = data.decode("utf-8")
    assert token.count(".") == 2  # looks like JWT

    # Header kid should match a valid row's kid
    hdr = jwt.get_unverified_header(token)
    assert "kid" in hdr

    # exp should be in the future
    payload = jwt.decode(token, options={"verify_signature": False})
    assert "exp" in payload
    assert payload["exp"] > int(time.time())


def test_auth_expired_token_has_past_exp(app_module, server):
    status, headers, data = _http_request(server.port, "POST", "/auth?expired=1")
    assert status == 200
    token = data.decode("utf-8")
    payload = jwt.decode(token, options={"verify_signature": False})
    assert payload["exp"] <= int(time.time())


def test_jwks_contains_all_valid_keys_and_fields(app_module, server):
    # count valid keys in DB
    now = int(time.time())
    [(valid_count,)] = _db_rows(
        "totally_not_my_privateKeys.db",
        "SELECT COUNT(*) FROM keys WHERE exp > ?",
        (now,)
    )

    status, headers, data = _http_request(server.port, "GET", "/.well-known/jwks.json")
    assert status == 200
    jwks = json.loads(data.decode("utf-8"))
    assert "keys" in jwks
    keys = jwks["keys"]
    assert isinstance(keys, list)

    # keys length should equal number of valid rows in DB
    assert len(keys) == valid_count

    # check required fields (alg, kty, use, kid, n, e) exist
    for k in keys:
        assert k.get("alg") == "RS256"
        assert k.get("kty") == "RSA"
        assert k.get("use") == "sig"
        assert "kid" in k and isinstance(k["kid"], str)
        assert "n" in k and isinstance(k["n"], str)
        assert "e" in k and isinstance(k["e"], str)


def test_auth_returns_500_when_no_keys(app_module, server_empty):
    status, headers, data = _http_request(server_empty.port, "POST", "/auth")
    assert status == 500
    assert b"No matching key" in data


def test_405s_for_unsupported_methods_and_paths(app_module, server):
    # Unsupported path
    s, h, d = _http_request(server.port, "GET", "/not-a-real-path")
    assert s == 405

    # Unsupported methods
    s, h, d = _http_request(server.port, "PUT", "/auth")
    assert s == 405
    s, h, d = _http_request(server.port, "PATCH", "/auth")
    assert s == 405
    s, h, d = _http_request(server.port, "DELETE", "/auth")
    assert s == 405
    # HEAD on non-supported
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=3)
    try:
        conn.request("HEAD", "/auth")
        resp = conn.getresponse()
        assert resp.status == 405
    finally:
        conn.close()
