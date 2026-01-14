import logging
import sys

# Configure logging to see what's happening
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

try:
    from trino.oauth2 import OAuth2Client
    from trino.oauth2.models import (
        ClientCredentialsConfig,
        DeviceCodeConfig,
        AuthorizationCodeConfig,
        OidcConfig
    )
except ImportError:
    print("Please install the package first or run from the source root.")
    sys.exit(1)

# Hydra Configuration (matching tests/configure_hydra.py)
HYDRA_PUBLIC_URL = "http://localhost:4444"
HYDRA_OIDC_ENDPOINT = f"{HYDRA_PUBLIC_URL}/.well-known/openid-configuration"

# Client Definitions (matching tests/configure_hydra.py)
CLIENT_CREDENTIALS_CLIENT = {
    "client_id": "client-credentials-client",
    "client_secret": "client-credentials-secret",
    "scope": "read write product1",
}

DEVICE_CODE_CLIENT_WITH_SECRETS = {
    "client_id": "device-code-client",
    "client_secret": "device-code-secret",
    "scope": "read write offline",
}

AUTHORIZATION_CODE_CLIENT = {
    "client_id": "auth-code-client-no-scopes",
    "client_secret": "auth-code-secret-no-scopes",
    "redirect_uris": ["http://localhost:61234/auth/token.callback"],
}


def example_client_credentials():
    print("\n--- Client Credentials Flow ---")

    oauth_client = OAuth2Client(
        config=ClientCredentialsConfig(
            client_id=CLIENT_CREDENTIALS_CLIENT["client_id"],
            client_secret=CLIENT_CREDENTIALS_CLIENT["client_secret"],
            scope=CLIENT_CREDENTIALS_CLIENT["scope"],
            url_config=OidcConfig(oidc_discovery_url=HYDRA_OIDC_ENDPOINT)
        )
    )

    try:
        token = oauth_client.token()
        print(f"Successfully obtained access token: {token[:20]}...")
    except Exception as e:
        print(f"Failed to obtain token: {e}")


def example_device_code():
    print("\n--- Device Code Flow ---")
    print("This flow requires user interaction. A URL will be printed.")

    oauth_client = OAuth2Client(
        config=DeviceCodeConfig(
            client_id=DEVICE_CODE_CLIENT_WITH_SECRETS["client_id"],
            client_secret=DEVICE_CODE_CLIENT_WITH_SECRETS["client_secret"],
            scope=DEVICE_CODE_CLIENT_WITH_SECRETS["scope"],
            url_config=OidcConfig(oidc_discovery_url=HYDRA_OIDC_ENDPOINT),
            poll_for_token=True
        )
    )

    try:
        # Without an automation_callback, this will print the verification URL
        # and wait for the user to complete the login in the browser.
        token = oauth_client.token()
        print(f"Successfully obtained access token: {token[:20]}...")
    except Exception as e:
        print(f"Failed to obtain token: {e}")


def example_authorization_code_flow():
    print("\n--- Authorization Code Flow ---")
    print("This flow requires user interaction via browser.")

    # Callback to handle the URL opening
    def open_browser_callback(url: str) -> str:
        print(f"Please open this URL in your browser to authenticate:\n{url}")
        # In a real app, you might use webbrowser.open(url)
        # But since this is a local hydra test, you might need to copy-paste it
        # or have the browser open.
        # webbrowser.open(url)

        # In the test environment, the 'redirect_uri' is localhost:61234.
        # The library expects to receive the full redirect URL including the code.
        print("\nAfter authenticating, you will see a connection error (because the callback server isn't running) " 
              "or be redirected to localhost:61234.")
        print("Copy the FULL URL you were redirected to (including ?code=...) and paste it here:")
        redirect_response = input("Redirected URL: ").strip()
        return redirect_response

    # NOTE: The AuthorizationCodeConfig normally expects a server or a way to catch the redirect.
    # The 'automation_callback' can be used to manually inject the result URL if we don't have a listener.
    # The library seems to support `automation_callback` which functions as a "get the redirect url" hook.

    oauth_client = OAuth2Client(
        config=AuthorizationCodeConfig(
            client_id=AUTHORIZATION_CODE_CLIENT["client_id"],
            client_secret=AUTHORIZATION_CODE_CLIENT["client_secret"],
            redirect_uri=AUTHORIZATION_CODE_CLIENT["redirect_uris"][0],
            url_config=OidcConfig(oidc_discovery_url=HYDRA_OIDC_ENDPOINT),
            automation_callback=open_browser_callback
        )
    )

    try:
        token = oauth_client.token()
        print(f"Successfully obtained access token: {token[:20]}...")
    except Exception as e:
        print(f"Failed to obtain token: {e}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        mode = sys.argv[1]
    else:
        print("Usage: python example.py [client_credentials|device_code|auth_code]")
        print("Defaulting to 'client_credentials' for this run.")
        mode = "client_credentials"

    if mode == "client_credentials":
        example_client_credentials()
    elif mode == "device_code":
        example_device_code()
    elif mode == "auth_code":
        example_authorization_code_flow()
    else:
        print(f"Unknown mode: {mode}")

