# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import sys
import os
import time

# Configure logging to see what's happening
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

try:
    from trino.oauth2 import OAuth2Client
    from trino.oauth2.models import (
        ClientCredentialsConfig,
        DeviceCodeConfig,
        AuthorizationCodeConfig,
        ManualUrlsConfig,
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
    print("--- Authorization Code Flow ---")

    # In a real app, you need a mechanism to capture the redirect.
    # Here we mock it or assume the user copy-pastes the code/url if supported.
    # The current library implementation requires a callback that returns the full redirect URL.

    def manual_input_callback(auth_url: str) -> str:
        print(f"Please visit this URL to authenticate: {auth_url}")
        redirect_url = input("Paste the full redirect URL here: ")
        return redirect_url

    client = OAuth2Client(
        config=AuthorizationCodeConfig(
            client_id="my-auth-code-client",
            client_secret="my-secret",
            scope="openid offline",
            redirect_uri="http://localhost:5555/callback",
            url_config=OidcConfig(oidc_discovery_url="https://hydra.example.com/.well-known/openid-configuration"),
            automation_callback=manual_input_callback
        )
    )

    token = client.token()
    print(f"Token: {token[:10]}...")


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

