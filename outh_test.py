import requests
import webbrowser
import base64
import hashlib
import json
import time
import secrets
from flask import Flask, request, make_response, redirect, url_for

app = Flask(__name__)

# === CONFIGURATION ===
def load_config():
    try:
        with open('local.config.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        raise Exception("config.json file not found. Please create it with the required configuration.")
    except json.JSONDecodeError:
        raise Exception("Invalid JSON in config.json file.")

config = load_config()
CLIENT_ID = config['client_id']
CLIENT_SECRET = config.get('client_secret', '')
AUTHORIZATION_ENDPOINT = config['authorization_endpoint']
TOKEN_ENDPOINT = config['token_endpoint']
REDIRECT_URI = "http://localhost:5555/callback"
SCOPES = config['scopes']
USE_PKCE = config.get('use_pkce', True)  # switch via config file

# === PKCE UTILS ===
def generate_pkce_pair():
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b'=').decode('utf-8')
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('utf-8')).digest()
    ).rstrip(b'=').decode('utf-8')
    return code_verifier, code_challenge


def decode_jwt(jwt_token):
    try:
        parts = jwt_token.split('.')
        if len(parts) != 3:
            return {}
        padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
        decoded_bytes = base64.urlsafe_b64decode(padded)
        return json.loads(decoded_bytes.decode('utf-8'))
    except Exception as e:
        return {"error": f"Failed to decode JWT: {str(e)}"}


# === GLOBAL STATE ===
latest_tokens = {}
received_at = 0
pkce_code_verifier = None
oauth_state = None


@app.route('/')
def index():
    global pkce_code_verifier, oauth_state

    # Optional PKCE setup
    code_challenge = None
    if USE_PKCE:
        pkce_code_verifier, code_challenge = generate_pkce_pair()
    oauth_state = base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b'=').decode('utf-8')

    # Build authorization URL
    auth_url = (
        f"{AUTHORIZATION_ENDPOINT}?"
        f"response_type=code&"
        f"client_id={CLIENT_ID}&"
        f"redirect_uri={REDIRECT_URI}&"
        #f"provider=google&"
        f"scope={SCOPES}&"
        f"state={oauth_state}&"
        f"prompt=login"
    )

    if USE_PKCE:
        auth_url += f"&code_challenge={code_challenge}&code_challenge_method=S256"

    print("Open the following URL in your browser:")
    print(auth_url)
    webbrowser.open(auth_url)
    return "Redirecting to login..."


@app.route('/callback')
def callback():
    global latest_tokens, received_at, pkce_code_verifier, oauth_state

    error = request.args.get('error')
    if error:
        desc = request.args.get('error_description', '')
        return f"Authorization failed: {error} - {desc}", 400

    code = request.args.get('code')
    if not code:
        return "Authorization failed. No code provided.", 400

    returned_state = request.args.get('state')
    if not returned_state or returned_state != oauth_state:
        return f"State mismatch or missing. Expected: {oauth_state}, got: {returned_state}", 400

    # Build token request payload
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
    }

    if USE_PKCE:
        data['code_verifier'] = pkce_code_verifier

    # Only include client_secret if it exists and PKCE-only mode isn’t set
    if CLIENT_SECRET and not USE_PKCE:
        data['client_secret'] = CLIENT_SECRET

    headers = {
        "accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    print("\n--- Token Exchange Attempt ---")
    print(f"Using PKCE: {USE_PKCE}")
    print(f"Payload (without secret): {json.dumps({k: v for k, v in data.items() if k != 'client_secret'}, indent=2)}")

    token_response = requests.post(TOKEN_ENDPOINT, data=data, headers=headers)

    # If provider rejects with invalid_client, retry without secret
    if (
        token_response.status_code in (400, 401)
        and "invalid_client" in token_response.text.lower()
        and "client_secret" in data
    ):
        print("Provider rejected client_secret — retrying token request without it.")
        data.pop("client_secret", None)
        token_response = requests.post(TOKEN_ENDPOINT, data=data, headers=headers)

    if token_response.status_code != 200:
        return f"Token refresh failed: {token_response.text}", 500

    latest_tokens = token_response.json()
    received_at = int(time.time())

    print("\nToken exchange succeeded:")
    print(json.dumps(latest_tokens, indent=2))

    return redirect(url_for('display_tokens'))

@app.route('/logout')
def logout():
    id_token = request.cookies.get('_a')
    print(f"ID Token from cookie: {id_token}")
    if id_token:
        logout_url = (
            f"http://localhost:8888/end_session?"
            f"post_logout_redirect_uri=http://localhost:5555"
            f"&id_token_hint={id_token}"
        )
        print("Open the following URL in your browser to logout:")
        print(logout_url)
        return redirect(logout_url)
    else:
        print("No ID token found in cookies.")


#TODO: Implement backchannel logout
@app.route('/backchannel', methods=['POST'])
def backchannel():
    print("Backchannel logout request received.")
    query_params = request.args.to_dict()
    headers = dict(request.headers)
    print("Query parameters received:", query_params)
    print("Headers received:", headers)

    try:
        form_data = request.form.to_dict()
        print("Form data received:", form_data)
    except Exception as e:
        print("Failed to parse form data:", str(e))
        form_data = None

    return "Backchannel logout processed.", 200

@app.route('/refresh')
def refresh():
    global latest_tokens, received_at
    refresh_token = latest_tokens.get('refresh_token')
    if not refresh_token:
        return "No refresh token available.", 400

    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': CLIENT_ID,
    }

    if CLIENT_SECRET:
        data['client_secret'] = CLIENT_SECRET

    token_response = requests.post(TOKEN_ENDPOINT, data=data)
    if token_response.status_code != 200:
        return f"Token refresh failed: {token_response.text}", 500

    new_tokens = token_response.json()
    latest_tokens.update(new_tokens)
    received_at = int(time.time())
    return redirect(url_for('display_tokens'))


@app.route('/tokens')
def display_tokens():
    global latest_tokens, received_at

    access_token = latest_tokens.get('access_token', '')
    id_token = latest_tokens.get('id_token', '')
    refresh_token = latest_tokens.get('refresh_token', '')
    expires_in = latest_tokens.get('expires_in', 3600)

    remaining_time = max(received_at + int(expires_in) - int(time.time()), 0)

    id_token_payload = decode_jwt(id_token)
    access_token_payload = decode_jwt(access_token)

    html = f"""
    <html>
        <head>
            <title>OAuth2 Tokens</title>
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 1000px; margin: auto; padding: 20px; }}
                table {{ width: 100%; table-layout: fixed; word-wrap: break-word; }}
                td, th {{ padding: 10px; border: 1px solid #ccc; vertical-align: top; }}
                code, pre {{ white-space: pre-wrap; word-wrap: break-word; }}
            </style>
            <script>
                let timeLeft = {remaining_time};
                function updateTimer() {{
                    if (timeLeft <= 0) {{
                        document.getElementById('timer').innerText = 'Access token expired';
                        return;
                    }}
                    let minutes = Math.floor(timeLeft / 60);
                    let seconds = timeLeft % 60;
                    document.getElementById('timer').innerText = 'Access token expiry: ' + minutes + 'm ' + seconds + 's';
                    timeLeft--;
                    setTimeout(updateTimer, 1000);
                }}
                window.onload = updateTimer;
            </script>
        </head>
        <body>
            <h2>OAuth2 Tokens</h2>
            <p><b>Using PKCE:</b> {USE_PKCE}</p>

            <h3>ID Token</h3>
            <table>
                <tr><th>Token</th><th>Decoded Payload</th></tr>
                <tr>
                    <td><code>{id_token}</code></td>
                    <td><pre>{json.dumps(id_token_payload, indent=2)}</pre></td>
                </tr>
            </table>

            <h3>Access Token</h3>
            <table>
                <tr><th>Token</th><th>Decoded Payload</th></tr>
                <tr>
                    <td><code>{access_token}</code></td>
                    <td><pre>{json.dumps(access_token_payload, indent=2)}</pre></td>
                </tr>
            </table>

            <h3>Refresh Token</h3>
            <table>
                <tr><th>Token</th><th>Decoded Payload</th></tr>
                <tr>
                    <td><code>{refresh_token}</code></td>
                    <td><i>Refresh tokens are opaque and cannot be decoded as JWTs</i></td>
                </tr>
            </table>

            <div style="margin-top: 20px;">
                <form action="/refresh" method="get" style="display: inline;">
                    <button type="submit">Refresh Tokens</button>
                </form>
                <span id="timer" style="margin-left: 20px; font-weight: bold;"></span>
            </div>

            <div style="margin-top: 20px;">
                <form action="/logout" method="get" style="display: inline;">
                    <button type="submit">Logout</button>
                </form>
                <span id="timer" style="margin-left: 20px; font-weight: bold;"></span>
            </div>

        </body>
    </html>
    """

    response = make_response(html)
    if id_token:
        response.set_cookie('_a', id_token, httponly=False, secure=False, samesite='Lax')

    return response


if __name__ == '__main__':
    print("Starting OAuth2 flow. Visit http://localhost:5555 in your browser.")
    app.run(port=5555)
