import os, json, jwt, hashlib, psycopg2
from datetime import datetime, timedelta
from google.cloud import bigquery
from google.oauth2 import service_account

# ── ENV VARS (configuradas no Vercel dashboard) ──────────────
NEON_URL    = os.environ["NEON_DATABASE_URL"]   # postgres://user:pass@host/db
BQ_PROJECT  = os.environ.get("BQ_PROJECT", "looker-integrations-402615")
BQ_TABLE    = os.environ.get("BQ_TABLE",   "looker-integrations-402615.tiktok_ads.conjunto mesclado 3")
SECRET_KEY  = os.environ["JWT_SECRET"]
SA_JSON     = os.environ.get("BQ_SERVICE_ACCOUNT_JSON", "")  # JSON como string

# ── NEON (PostgreSQL) ────────────────────────────────────────
def get_db():
    return psycopg2.connect(NEON_URL, sslmode="require")

def init_db():
    """Cria tabela de usuários se não existir"""
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         SERIAL PRIMARY KEY,
            username   TEXT UNIQUE NOT NULL,
            password   TEXT NOT NULL,
            role       TEXT NOT NULL DEFAULT 'client',
            client     TEXT,
            campaigns  TEXT[]  DEFAULT '{}'
        )
    """)
    # Admin padrão
    cur.execute("""
        INSERT INTO users (username, password, role, client, campaigns)
        VALUES (%s, %s, 'admin', 'inflr Admin', '{}')
        ON CONFLICT (username) DO NOTHING
    """, ('admin', _hash('admin123')))
    conn.commit()
    cur.close(); conn.close()

# ── AUTH ─────────────────────────────────────────────────────
def _hash(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def verify_user(username: str, password: str):
    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "SELECT username, role, client, campaigns FROM users WHERE username=%s AND password=%s",
        (username, _hash(password))
    )
    row = cur.fetchone()
    cur.close(); conn.close()
    if not row:
        return None
    return {"username": row[0], "role": row[1], "client": row[2], "campaigns": list(row[3] or [])}

def create_token(user: dict) -> str:
    payload = {
        "sub":       user["username"],
        "role":      user["role"],
        "client":    user["client"],
        "campaigns": user["campaigns"],
        "exp":       datetime.utcnow() + timedelta(hours=12)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

def get_token_from_request(environ) -> dict:
    auth = environ.get("HTTP_AUTHORIZATION", "")
    if not auth.startswith("Bearer "):
        raise PermissionError("Token não encontrado.")
    return decode_token(auth[7:])

# ── BIGQUERY ─────────────────────────────────────────────────
def get_bq():
    if SA_JSON:
        info  = json.loads(SA_JSON)
        creds = service_account.Credentials.from_service_account_info(info)
        return bigquery.Client(credentials=creds, project=BQ_PROJECT)
    return bigquery.Client(project=BQ_PROJECT)

def build_campaign_filter(user: dict) -> str:
    """Monta o WHERE baseado nas palavras-chave do cliente"""
    if user["role"] == "admin":
        return "1=1"
    keywords = user.get("campaigns", [])
    if not keywords:
        return "1=0"  # sem palavras-chave = sem dados
    conditions = " OR ".join(
        [f"UPPER(CAMPAIGN_NAME) LIKE '%{kw.upper()}%'" for kw in keywords]
    )
    return f"({conditions})"

# ── RESPONSE HELPERS ─────────────────────────────────────────
def cors_headers():
    return {
        "Access-Control-Allow-Origin":  "*",
        "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization, Content-Type",
        "Content-Type": "application/json"
    }

def json_response(data, status=200):
    return {
        "statusCode": status,
        "headers":    cors_headers(),
        "body":       json.dumps(data, default=str)
    }

def error_response(msg, status=400):
    return json_response({"error": msg}, status)
