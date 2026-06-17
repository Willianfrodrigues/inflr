import json, hashlib
from http.server import BaseHTTPRequestHandler
from _helpers import (get_db, get_token_from_request,
                      json_response, error_response, cors_headers)

def _hash(pw): return hashlib.sha256(pw.encode()).hexdigest()

class handler(BaseHTTPRequestHandler):

    def do_OPTIONS(self):
        self.send_response(200)
        for k, v in cors_headers().items(): self.send_header(k, v)
        self.end_headers()

    def _send(self, resp):
        self.send_response(resp["statusCode"])
        for k, v in resp["headers"].items(): self.send_header(k, v)
        self.end_headers()
        self.wfile.write(resp["body"].encode())

    def _require_admin(self):
        user = get_token_from_request(self.headers.__dict__.get("_headers_dict", {}))
        if user.get("role") != "admin":
            raise PermissionError("Acesso negado.")
        return user

    # GET /api/users — listar todos
    def do_GET(self):
        try:
            # pega token do header
            auth = self.headers.get("Authorization", "")
            import jwt, os
            user = jwt.decode(auth[7:], os.environ["JWT_SECRET"], algorithms=["HS256"])
            if user["role"] != "admin":
                return self._send(error_response("Acesso negado.", 403))

            conn = get_db(); cur = conn.cursor()
            cur.execute("SELECT username, role, client, campaigns FROM users ORDER BY id")
            rows = [{"username":r[0],"role":r[1],"client":r[2],"campaigns":list(r[3] or [])} for r in cur.fetchall()]
            cur.close(); conn.close()
            self._send(json_response(rows))

        except Exception as e:
            self._send(error_response(str(e), 500))

    # POST /api/users — criar usuário
    def do_POST(self):
        try:
            auth = self.headers.get("Authorization", "")
            import jwt, os
            user = jwt.decode(auth[7:], os.environ["JWT_SECRET"], algorithms=["HS256"])
            if user["role"] != "admin":
                return self._send(error_response("Acesso negado.", 403))

            length = int(self.headers.get("Content-Length", 0))
            body   = json.loads(self.rfile.read(length))

            conn = get_db(); cur = conn.cursor()
            cur.execute("""
                INSERT INTO users (username, password, role, client, campaigns)
                VALUES (%s, %s, 'client', %s, %s)
                ON CONFLICT (username) DO NOTHING
                RETURNING id
            """, (
                body["username"],
                _hash(body["password"]),
                body.get("client", ""),
                body.get("campaigns", [])
            ))
            inserted = cur.fetchone()
            conn.commit(); cur.close(); conn.close()

            if not inserted:
                return self._send(error_response("Usuário já existe.", 400))
            self._send(json_response({"ok": True}))

        except Exception as e:
            self._send(error_response(str(e), 500))

    # DELETE /api/users — remover (passa username no body)
    def do_DELETE(self):
        try:
            auth = self.headers.get("Authorization", "")
            import jwt, os
            user = jwt.decode(auth[7:], os.environ["JWT_SECRET"], algorithms=["HS256"])
            if user["role"] != "admin":
                return self._send(error_response("Acesso negado.", 403))

            length = int(self.headers.get("Content-Length", 0))
            body   = json.loads(self.rfile.read(length))
            username = body.get("username")

            if username == "admin":
                return self._send(error_response("Não é possível remover o admin.", 400))

            conn = get_db(); cur = conn.cursor()
            cur.execute("DELETE FROM users WHERE username=%s", (username,))
            conn.commit(); cur.close(); conn.close()
            self._send(json_response({"ok": True}))

        except Exception as e:
            self._send(error_response(str(e), 500))
