"""
Traefik forwardAuth gate — cookie-based access control for non-production environments.

Replaces basic auth so users authenticate once via a simple password form and get a
30-day HMAC-signed cookie. No more repeated browser prompts on logout/multi-user demos.

Environment variables:
    GATE_PASSWORD   — the plaintext password users enter (required)
    GATE_SECRET_KEY — secret used to HMAC-sign the cookie (required)
    GATE_COOKIE_MAX_AGE — cookie lifetime in seconds (default: 30 days)
    GATE_COOKIE_NAME — cookie name (default: __boxrank_gate)
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
COOKIE_NAME = os.environ.get("GATE_COOKIE_NAME", "__boxrank_gate")
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
<title>Access Required - BoxRank</title>
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
  <div class="logo">
    <svg viewBox="94 11 406 78" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M150.6 60.9016C150.6 72.1016 142.6 76.1016 134.6 76.1016H103.4L102.6 75.3016V20.9016L103.4 20.1016H133C141 20.1016 149 24.1016 149 34.5016C149 40.1016 146.6 44.9016 141 46.5016V47.3016C147.4 48.9016 150.6 53.7016 150.6 60.9016ZM134.6 36.9016C134.6 34.5016 133.8 32.1016 129 32.1016H117.8L117 32.9016V40.9016L117.8 41.7016H129C133.8 41.7016 134.6 39.3016 134.6 36.9016ZM136.2 58.5016C136.2 54.5016 134.6 52.9016 129 52.9016H117.8L117 53.7016V63.3016L117.8 64.1016H129C134.6 64.1016 136.2 62.5016 136.2 58.5016ZM155.416 48.1016C155.416 29.7016 166.616 19.3016 183.416 19.3016C200.216 19.3016 211.416 29.7016 211.416 48.1016C211.416 66.5016 200.216 76.9016 183.416 76.9016C166.616 76.9016 155.416 66.5016 155.416 48.1016ZM169.816 48.1016C169.816 59.3016 174.616 64.9016 183.416 64.9016C192.216 64.9016 197.016 59.3016 197.016 48.1016C197.016 36.9016 192.216 31.3016 183.416 31.3016C174.616 31.3016 169.816 36.9016 169.816 48.1016ZM264.234 75.3016L263.434 76.1016H256.234L254.634 75.3016L240.234 56.1016H239.434L225.034 75.3016L223.434 76.1016H216.234L215.434 75.3016V64.9016L229.834 47.3016V46.5016L216.234 31.3016V20.9016L217.034 20.1016H224.234L225.834 20.9016L239.434 37.7016H240.234L253.834 20.9016L255.434 20.1016H262.634L263.434 20.9016V31.3016L249.834 46.5016V47.3016L264.234 64.9016V75.3016ZM321.869 37.7016C321.869 46.5016 317.069 51.3016 311.469 53.7016V54.5016L320.269 64.9016V75.3016L319.469 76.1016H313.069L311.469 75.3016L295.469 56.1016L293.869 55.3016H288.269L287.469 56.1016V75.3016L286.669 76.1016H273.869L273.069 75.3016V20.9016L273.869 20.1016H301.869C313.869 20.1016 321.869 26.5016 321.869 37.7016ZM307.469 37.7016C307.469 32.9016 305.069 32.1016 301.869 32.1016H288.269L287.469 32.9016V42.5016L288.269 43.3016H301.869C305.069 43.3016 307.469 42.5016 307.469 37.7016ZM365.066 75.3016L361.866 66.5016L360.266 65.7016H341.866L340.266 66.5016L337.066 75.3016L336.266 76.1016H326.666L325.866 75.3016V64.9016L343.466 20.9016L344.266 20.1016H357.866L358.666 20.9016L376.266 64.9016V75.3016L375.466 76.1016H365.866L365.066 75.3016ZM350.666 37.7016L345.066 52.9016L345.866 53.7016H356.266L357.066 52.9016L351.466 37.7016H350.666ZM383.459 20.9016L384.259 20.1016H397.859L399.459 20.9016L418.659 51.3016H419.459V20.9016L420.259 20.1016H433.059L433.859 20.9016V75.3016L433.059 76.1016H419.459L417.859 75.3016L398.659 44.9016H397.859V75.3016L397.059 76.1016H384.259L383.459 75.3016V20.9016ZM490.622 75.3016L489.822 76.1016H483.422L481.822 75.3016L464.222 57.7016H463.422L459.422 61.7016V75.3016L458.622 76.1016H445.822L445.022 75.3016V20.9016L445.822 20.1016H458.622L459.422 20.9016V42.5016H460.222L481.822 20.9016L483.422 20.1016H489.022L489.822 20.9016V31.3016L473.822 47.3016V48.1016L490.622 64.9016V75.3016Z" fill="white"/></svg>
  </div>
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
