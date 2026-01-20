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

import os
import time
import sys
import requests

HYDRA_ADMIN_URL = os.getenv("HYDRA_ADMIN_URL", "http://localhost:4445")
HYDRA_PUBLIC_URL = os.getenv("HYDRA_PUBLIC_URL", "http://localhost:4444")
TOKEN_ENDPOINT = f"{HYDRA_PUBLIC_URL}/oauth2/token"
DEVICE_AUTH_ENDPOINT = f"{HYDRA_PUBLIC_URL}/oauth2/device/auth"
HYDRA_OIDC_ENDPOINT = f"{HYDRA_PUBLIC_URL}/.well-known/openid-configuration"
HYDRA_PUBLIC_KEY = f"{HYDRA_PUBLIC_URL}/.well-known/jwks.json"

CLIENT_CREDENTIALS_CLIENT = {
    "client_id": "client-credentials-client",
    "client_secret": "client-credentials-secret",
    "grant_types": ["client_credentials"],
    "response_types": ["token"],
    "scope": "read write product1",
    "token_endpoint_auth_method": "client_secret_post"
}

CLIENT_CREDENTIALS_WITH_AUDIENCE = {
    "client_id": "client-credentials-audience",
    "client_secret": "client-credentials-audience-secret",
    "grant_types": ["client_credentials"],
    "response_types": ["token"],
    "audience": ["aud1", "aud2"],
    "token_endpoint_auth_method": "client_secret_post"
}

DEVICE_CODE_CLIENT_WITH_SECRETS = {
    "client_id": "device-code-client",
    "client_secret": "device-code-secret",
    "grant_types": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
    "response_types": ["token"],
    "scope": "read write offline",
    "token_endpoint_auth_method": "client_secret_post"
}

DEVICE_CODE_CLIENT_NO_SECRETS_WITH_SCOPES = {
    "client_id": "device-code-client-no-secrets-w-scopes",
    "grant_types": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
    "response_types": ["token"],
    "scope": "product1 offline",
    "token_endpoint_auth_method": "none"
}

DEVICE_CODE_CLIENT_NO_SECRETS_WITH_SCOPES_AUDIENCE = {
    "client_id": "device-code-client-no-secrets-w-scopes-audience",
    "grant_types": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
    "response_types": ["token"],
    "scope": "offline product3 product4",
    "audience": ["aud3"],
    "token_endpoint_auth_method": "none"
}

# [NEW] Configuration for Authorization Code Flow
AUTHORIZATION_CODE_CLIENT = {
    "client_id": "auth-code-client-no-scopes",
    "client_secret": "auth-code-secret-no-scopes",
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "redirect_uris": ["http://localhost:61234/auth/token.callback"],
    "token_endpoint_auth_method": "client_secret_post"
}

AUTHORIZATION_CODE_CLIENT_WITH_SCOPES = {
    "client_id": "auth-code-client-with-scopes",
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "scope": "openid offline",
    "redirect_uris": ["http://localhost:61234/auth/token.callback"],
    "token_endpoint_auth_method": "none"
}

# [NEW] Bad configurations for testing
BAD_CLIENT_CONFIG = {
    "client_id": "bad-client-id",
    "client_secret": "bad-client-secret",
    "scope": "product-bad"
}

def wait_for_hydra(max_retries=30, delay=2):
    """Wait for Hydra to be ready before proceeding."""
    print(f"Waiting for Hydra at {HYDRA_ADMIN_URL}/health/ready to be ready...")
    for i in range(max_retries):
        try:
            response = requests.get(f"{HYDRA_ADMIN_URL}/health/ready", timeout=5)
            if response.status_code == 200:
                print(f"Hydra is ready at {HYDRA_ADMIN_URL}!")
                return True
        except requests.exceptions.RequestException:
            pass
        print(f"Attempt {i+1}/{max_retries}: Hydra not ready yet, waiting {delay}s...")
        time.sleep(delay)

    print(f"ERROR: Hydra did not become ready after {max_retries * delay} seconds")
    return False

def create_oauth_client(client_data):
    """Creates a single OAuth2 client."""
    client_id = client_data["client_id"]
    url = f"{HYDRA_ADMIN_URL}/clients"

    # Check if client exists
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        for client in response.json():
            if client.get('client_id') == client_id:
                print(f"Client '{client_id}' already exists. Deleting it.")
                delete_url = f"{url}/{client_id}"
                delete_response = requests.delete(delete_url, timeout=10)
                delete_response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error communicating with Hydra: {e}")
        return

    # Create client
    try:
        response = requests.post(url, json=client_data, timeout=10)
        response.raise_for_status()
        print(f"Client '{client_id}' created successfully.")
    except requests.exceptions.HTTPError as e:
        print(f"Failed to create client '{client_id}': {e.response.text}")
        raise

if __name__ == "__main__":
    # Wait for Hydra to be ready
    if not wait_for_hydra():
        sys.exit(1)

    create_oauth_client(CLIENT_CREDENTIALS_CLIENT)
    create_oauth_client(CLIENT_CREDENTIALS_WITH_AUDIENCE)
    create_oauth_client(DEVICE_CODE_CLIENT_WITH_SECRETS)
    create_oauth_client(DEVICE_CODE_CLIENT_NO_SECRETS_WITH_SCOPES)
    create_oauth_client(DEVICE_CODE_CLIENT_NO_SECRETS_WITH_SCOPES_AUDIENCE)
    create_oauth_client(AUTHORIZATION_CODE_CLIENT)
    create_oauth_client(AUTHORIZATION_CODE_CLIENT_WITH_SCOPES)
