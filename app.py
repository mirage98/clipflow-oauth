import os
import secrets
import requests
import psycopg
from psycopg.rows import dict_row
from flask import Flask, redirect, request, session

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", secrets.token_hex(32))

CLIENT_KEY = os.environ.get("TIKTOK_CLIENT_KEY", "")
CLIENT_SECRET = os.environ.get("TIKTOK_CLIENT_SECRET", "")
REDIRECT_URI = "https://clipflow-oauth.onrender.com/callback"
SCOPES = "user.info.basic,video.publish"

def get_db():
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        raise RuntimeError("DATABASE_URL is not configured")
    return psycopg.connect(db_url, row_factory=dict_row)

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tokens (
                id BIGSERIAL PRIMARY KEY,
                access_token TEXT,
                refresh_token TEXT,
                expires_in INTEGER,
                scope TEXT
            )
        """)

def save_token(data):
    init_db()
    with get_db() as conn:
        conn.execute(
            "INSERT INTO tokens(access_token,refresh_token,expires_in,scope) VALUES(%s,%s,%s,%s)",
            (
                data.get("access_token"),
                data.get("refresh_token"),
                data.get("expires_in"),
                data.get("scope"),
            )
        )

@app.route("/")
def home():
    return '<h2>ClipFlow</h2><a href="/login">Connect TikTok</a>'

@app.route("/login")
def login():
    if not CLIENT_KEY:
        return "TIKTOK_CLIENT_KEY is not configured.", 500

    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state

    params = {
        "client_key": CLIENT_KEY,
        "response_type": "code",
        "scope": SCOPES,
        "redirect_uri": REDIRECT_URI,
        "state": state,
    }
    return redirect(
        "https://www.tiktok.com/v2/auth/authorize/?"
        + requests.compat.urlencode(params)
    )

@app.route("/callback")
def callback():
    if request.args.get("error"):
        return "TikTok authorization was denied.", 400

    code = request.args.get("code")
    returned_state = request.args.get("state")

    if not code:
        return "No authorization code received.", 400

    if not returned_state or returned_state != session.get("oauth_state"):
        return "Invalid OAuth state.", 400

    if not CLIENT_KEY or not CLIENT_SECRET:
        return "Server credentials are not configured.", 500

    response = requests.post(
        "https://open.tiktokapis.com/v2/oauth/token/",
        data={
            "client_key": CLIENT_KEY,
            "client_secret": CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": REDIRECT_URI,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
    )

    data = response.json()

    if response.status_code != 200 or "access_token" not in data:
        return "Token exchange failed. Check server configuration.", 400

    save_token(data)
    session.pop("oauth_state", None)
    return "TikTok authorization completed. Token saved on server."


@app.route("/api/token")
def api_token():
    from flask import jsonify
    import hmac

    supplied = request.headers.get("X-ClipFlow-Key", "")
    expected = os.environ.get("TOKEN_API_SECRET", "")

    if not expected or not hmac.compare_digest(supplied, expected):
        return jsonify({"error": "unauthorized"}), 401

    try:
        init_db()
        with get_db() as conn:
            row = conn.execute(
                "SELECT * FROM tokens ORDER BY id DESC LIMIT 1"
            ).fetchone()
    except Exception:
        app.logger.exception("Database error in token API")
        return jsonify({"error": "database_error"}), 500

    if not row:
        return jsonify({"error": "token_not_found"}), 404

    return jsonify(row)

if __name__ == "__main__":.
    @app.route("/api/fingerprint")
def fingerprint():
    import hashlib
    from flask import jsonify

    secret = os.environ.get("TOKEN_API_SECRET", "")
    return jsonify({
        "fingerprint": hashlib.sha256(secret.encode()).hexdigest()[:16],
        "length": len(secret)
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
