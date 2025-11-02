import os
import json
import base64
import secrets
from tqdm import tqdm
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from urllib.parse import urlparse, parse_qs, urlencode
from typing import Optional
import requests
from dotenv import load_dotenv


load_dotenv()


AUTH_URL = "https://myanimelist.net/v1/oauth2/authorize"
TOKEN_URL = "https://myanimelist.net/v1/oauth2/token"
TOKEN_CACHE = ".request.json"


_TOKEN: Optional[str] = None
_LAST_CALL: float = 0.0  # monotonic timestamp of last outgoing HTTP call


def get_bearer_token() -> str:
    """Return a valid bearer access token.

    Reuses cached token from TOKEN_CACHE when present. If missing/expired,
    runs an interactive OAuth2 Authorization Code + PKCE (plain) flow and
    stores the full token response to TOKEN_CACHE for reuse.
    """
    global _TOKEN
    if _TOKEN:
        return _TOKEN
    # Try cached token first
    if os.path.exists(TOKEN_CACHE):
        try:
            with open(TOKEN_CACHE, "r", encoding="utf-8") as f:
                data = json.load(f)
            tok = data.get("access_token")
            if tok:
                _TOKEN = tok
                return _TOKEN
        except Exception:
            pass

    client_id = os.getenv("MAL_CLIENT_ID")
    client_secret = os.getenv("MAL_CLIENT_SECRET")
    redirect_uri = os.getenv("MAL_REDIRECT_URI")

    # PKCE (plain)
    code_verifier, code_challenge = _generate_pkce(64)

    # Build authorize URL (Scheme 2 with Basic at token step)
    params = {
        "response_type": "code",
        "client_id": client_id,
        "state": secrets.token_urlsafe(16),
        "redirect_uri": redirect_uri,
        "scope": "write:users offline_access",
        "code_challenge": code_challenge,
        "code_challenge_method": "plain",
    }
    authorize_url = f"{AUTH_URL}?{urlencode(params)}"

    # Wait for authorization code on the redirect uri
    auth_code = _wait_for_authorization_code(redirect_uri, authorize_url)

    # Exchange code for token (HTTP Basic)
    headers = {
        "Authorization": _basic_auth_header(client_id, client_secret),
        "Content-Type": "application/x-www-form-urlencoded",
    }
    body = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }
    resp = requests.post(TOKEN_URL, data=body, headers=headers, timeout=30)
    if resp.status_code != 200:
        raise RuntimeError(f"Token request failed: {resp.status_code} {resp.text}")
    token_json = resp.json()
    _save_token(token_json)
    return _TOKEN  # type: ignore[return-value]


def auth_headers() -> dict:
    """Return Authorization header with a valid bearer token."""
    return {"Authorization": f"Bearer {get_bearer_token()}"}


def _generate_pkce(length: int) -> tuple[str, str]:
    """Generate PKCE plain pair (verifier == challenge)."""
    if not (43 <= length <= 128):
        length = 64
    verifier = secrets.token_urlsafe(length)
    challenge = verifier
    return verifier, challenge


def _basic_auth_header(client_id: str, client_secret: str) -> str:
    creds = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    return f"Basic {creds}"


def _wait_for_authorization_code(redirect_uri: str, authorize_url: str) -> str:
    """Start a one-shot local HTTP server and return the 'code' query value."""
    code_holder: dict[str, Optional[str]] = {"code": None}

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # type: ignore[override]
            q = parse_qs(urlparse(self.path).query)
            code_holder["code"] = (q.get("code") or [None])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Authorized. You can close this window.")
        def log_message(self, *args, **kwargs):  # silence
            return

    u = urlparse(redirect_uri)
    host = u.hostname or "localhost"
    port = u.port or 8080
    httpd = HTTPServer((host, port), _Handler)
    print(f"Open this URL to authorize:\n{authorize_url}")
    httpd.handle_request()  # block for a single request
    code = code_holder.get("code")
    if not code:
        raise RuntimeError("Authorization code not received")
    print("Authorization code received.\n\n\n")
    return code


def _save_token(token_json: dict) -> None:
    global _TOKEN
    try:
        with open(TOKEN_CACHE, "w", encoding="utf-8") as f:
            json.dump(token_json, f, ensure_ascii=False, indent=2)
    except Exception:
        pass
    _TOKEN = token_json.get("access_token")


def _load_token() -> Optional[dict]:
    if os.path.exists(TOKEN_CACHE):
        try:
            with open(TOKEN_CACHE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    return None


def refresh_bearer_token() -> str:
    client_id = os.getenv("MAL_CLIENT_ID")
    client_secret = os.getenv("MAL_CLIENT_SECRET")
    token_json = _load_token() or {}
    refresh = token_json.get("refresh_token")
    if not refresh:
        # fallback to interactive
        return get_bearer_token()
    headers = {
        "Authorization": _basic_auth_header(client_id, client_secret),
        "Content-Type": "application/x-www-form-urlencoded",
    }
    body = {
        "grant_type": "refresh_token",
        "refresh_token": refresh,
    }
    resp = requests.post(TOKEN_URL, data=body, headers=headers, timeout=30)
    if resp.status_code != 200:
        # re-authorize
        if os.path.exists(TOKEN_CACHE):
            try:
                os.remove(TOKEN_CACHE)
            except Exception:
                pass
        return get_bearer_token()
    new_token = resp.json()
    _save_token(new_token)
    return _TOKEN


def api_get(
    url: str,
    params: dict | None = None,
    timeout: int = 240,
    retries: int = 3,
    backoff: float = 1.0,
) -> requests.Response:
    """GET wrapper that retries on timeouts and refreshes on 401 automatically.

    Retries on requests Timeout/ConnectionError with exponential backoff.
    On 401, attempts refresh, then re-authorizes as a final fallback.
    """
    delay = backoff
    for attempt in range(retries):
        try:
            headers = auth_headers()
            _throttle()
            stop = _start_countdown(timeout, f"timeout (try {attempt+1}/{retries})")
            try:
                r = requests.get(url, headers=headers, params=params, timeout=timeout)
            finally:
                stop()
            if r.status_code != 401:
                return r
            # 401: try refresh then final reauth
            refresh_bearer_token()
            headers = auth_headers()
            _throttle()
            stop = _start_countdown(timeout, f"timeout (refresh {attempt+1}/{retries})")
            try:
                r = requests.get(url, headers=headers, params=params, timeout=timeout)
            finally:
                stop()
            if r.status_code != 401:
                return r
            # Final fallback: return 504 (do not re-authorize interactively here)
            resp = requests.Response()
            resp.status_code = 504
            resp._content = b"Final retry failed after refresh; returning 504"
            resp.url = url
            return resp
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            if attempt == retries - 1:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 30)


def _throttle(min_interval: float = 1.0) -> None:
    """Ensure at least `min_interval` seconds between outbound HTTP calls."""
    global _LAST_CALL
    now = time.monotonic()
    if _LAST_CALL > 0:
        to_sleep = min_interval - (now - _LAST_CALL)
        if to_sleep > 0:
            time.sleep(to_sleep)
    _LAST_CALL = time.monotonic()


def _start_countdown(seconds: int, label: str):
    """Start a background countdown indicator using tqdm; returns a stopper callable."""
    bar = tqdm(total=seconds, desc=label, unit="s", leave=False)
    stop_event = threading.Event()

    def run():
        elapsed = 0
        while not stop_event.is_set() and elapsed < seconds:
            time.sleep(1)
            elapsed += 1
            try:
                bar.update(1)
                bar.set_postfix_str(f"remaining={max(0, seconds - elapsed)}s")
            except Exception:
                pass
        try:
            bar.close()
        except Exception:
            pass

    t = threading.Thread(target=run, daemon=True)
    t.start()

    def stop():
        stop_event.set()
        try:
            t.join(timeout=0.2)
        except Exception:
            pass
        try:
            bar.close()
        except Exception:
            pass

    return stop
