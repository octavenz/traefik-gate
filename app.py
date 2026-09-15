"""
Traefik forwardAuth gate — cookie-based access control for non-production environments.

Replaces basic auth so users authenticate once via a simple password form and get a
30-day HMAC-signed cookie. No more repeated browser prompts on logout/multi-user demos.

Environment variables:
    GATE_PASSWORD   — the plaintext password users enter (required)
    GATE_SECRET_KEY — secret used to HMAC-sign the cookie (required)
    GATE_COOKIE_MAX_AGE — cookie lifetime in seconds (default: 30 days)
    GATE_COOKIE_NAME — cookie name (default: __auth_gate)
"""

import hashlib
import hmac
import html
import os
import time
import urllib.parse
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from string import Template

GATE_PASSWORD = os.environ["GATE_PASSWORD"]
GATE_SECRET_KEY = os.environ["GATE_SECRET_KEY"].encode()
COOKIE_MAX_AGE = int(os.environ.get("GATE_COOKIE_MAX_AGE", str(30 * 24 * 3600)))
COOKIE_NAME = os.environ.get("GATE_COOKIE_NAME", "__auth_gate")
LOGIN_PATH = "/__gate/login"


def sign(value: str) -> str:
    return hmac.new(GATE_SECRET_KEY, value.encode(), hashlib.sha256).hexdigest()


def make_cookie_value() -> str:
    expires = str(int(time.time()) + COOKIE_MAX_AGE)
    sig = sign(expires)
    return f"{expires}:{sig}"


def verify_cookie(cookie_value: str) -> bool:
    try:
        expires, sig = cookie_value.rsplit(":", 1)
        if int(expires) < int(time.time()):
            return False
        return hmac.compare_digest(sig, sign(expires))
    except (ValueError, TypeError):
        return False


LOGIN_PAGE = Template("""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Access Required</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'DM Sans', -apple-system, system-ui, sans-serif;
    background: #0c0c0d;
    color: #fff;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    min-height: 100dvh;
    padding: 24px;
  }
  .card {
    background: rgba(26, 26, 27, 0.8);
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 16px;
    padding: 48px 40px;
    max-width: 380px;
    width: 100%;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
  }
  .logo {
    display: block;
    margin-bottom: 32px;
  }
  .logo svg {
    display: block;
    height: 20px;
    width: auto;
  }
  h1 {
    font-size: 20px;
    font-weight: 700;
    margin-bottom: 8px;
    letter-spacing: -0.01em;
    color: #fff;
  }
  .subtitle {
    font-size: 14px;
    color: rgba(255, 255, 255, 0.5);
    margin-bottom: 28px;
    line-height: 1.5;
  }
  .field {
    margin-bottom: 20px;
  }
  .field label {
    display: block;
    font-size: 13px;
    font-weight: 500;
    color: rgba(255, 255, 255, 0.7);
    margin-bottom: 8px;
  }
  .field input {
    width: 100%;
    padding: 12px 16px;
    border-radius: 8px;
    border: 1px solid rgba(255, 255, 255, 0.2);
    background: rgba(255, 255, 255, 0.08);
    color: #fff;
    font-family: inherit;
    font-size: 15px;
    transition: border-color 0.15s, background 0.15s;
  }
  .field input::placeholder {
    color: rgba(255, 255, 255, 0.35);
  }
  .field input:focus {
    outline: none;
    border-color: rgba(255, 255, 255, 0.4);
    background: rgba(255, 255, 255, 0.12);
  }
  button {
    width: 100%;
    padding: 12px 20px;
    border-radius: 8px;
    border: none;
    background: #fff;
    color: #0c0c0d;
    font-family: inherit;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.15s, transform 0.1s;
  }
  button:hover {
    background: rgba(255, 255, 255, 0.88);
  }
  button:active {
    transform: scale(0.98);
  }
  .error {
    background: rgba(248, 113, 113, 0.1);
    border: 1px solid rgba(248, 113, 113, 0.25);
    border-radius: 8px;
    padding: 12px 16px;
    margin-bottom: 20px;
    font-size: 13px;
    color: #f87171;
  }
  .footer {
    margin-top: 28px;
    text-align: center;
    font-size: 12px;
    color: rgba(255, 255, 255, 0.25);
  }
</style>
</head>
<body>
<div class="card">
  <h1>Access Required</h1>
  <p class="subtitle">Enter the password to continue to this environment.</p>
  $error
  <form method="POST">
    <input type="hidden" name="next" value="$next">
    <div class="field">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" placeholder="Enter password" autofocus required>
    </div>
    <button type="submit">Continue</button>
  </form>
  <p class="footer">Protected environment</p>
</div>
</body>
</html>""")


class GateHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path.startswith(LOGIN_PATH):
            self._serve_login_page()
            return
        # forwardAuth check — verify cookie
        cookie_header = self.headers.get("Cookie", "")
        cookies = SimpleCookie()
        try:
            cookies.load(cookie_header)
        except Exception:
            pass

        morsel = cookies.get(COOKIE_NAME)
        if morsel and verify_cookie(morsel.value):
            self.send_response(HTTPStatus.OK)
            self.end_headers()
        else:
            # Redirect to login — pass the original URL so we can redirect back.
            original_url = self.headers.get("X-Forwarded-Uri", "/")
            original_host = self.headers.get("X-Forwarded-Host", "")
            original_proto = self.headers.get("X-Forwarded-Proto", "https")
            next_url = f"{original_proto}://{original_host}{original_url}" if original_host else original_url
            login_url = f"{original_proto}://{original_host}{LOGIN_PATH}?next={urllib.parse.quote(next_url)}"
            self.send_response(HTTPStatus.TEMPORARY_REDIRECT)
            self.send_header("Location", login_url)
            self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode()
        params = urllib.parse.parse_qs(body)

        password = params.get("password", [""])[0]
        next_url = params.get("next", ["/"])[0]

        if password == GATE_PASSWORD:
            cookie_value = make_cookie_value()
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", next_url)
            self.send_header(
                "Set-Cookie",
                f"{COOKIE_NAME}={cookie_value}; Path=/; Max-Age={COOKIE_MAX_AGE}; "
                f"HttpOnly; Secure; SameSite=Lax",
            )
            self.end_headers()
        else:
            self._serve_login_page(error="Incorrect password.", next_url=next_url)

    def _serve_login_page(self, error: str = "", next_url: str = ""):
        if not next_url:
            qs = urllib.parse.urlparse(self.path).query
            next_url = urllib.parse.parse_qs(qs).get("next", ["/"])[0]

        error_html = f'<p class="error">{error}</p>' if error else ""
        page = LOGIN_PAGE.substitute(error=error_html, next=html.escape(next_url, quote=True))
        body = page.encode()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    server = HTTPServer(("0.0.0.0", port), GateHandler)
    print(f"Gate listening on :{port}")
    server.serve_forever()
