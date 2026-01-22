# Trino OAuth2 Python Library

The library supports OAuth 2.0 authentication flows including [Client Credentials](https://datatracker.ietf.org/doc/html/rfc6749#section-1.3.4), [Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628), and Authorization Code flows. This package is designed to make interaction with OAuth 2.0 flows as simple as possible.

## Features

- **Client Credentials Flow**: For machine-to-machine communication.
- **Device Code Flow**: For devices with limited input capabilities.
- **Authorization Code Flow**: For standard user authentication.
- **Secure Token Storage**: Integration with system keyring via `keyring` and `keyrings.cryptfile`.
- **OIDC Discovery**: Automatic configuration using OpenID Connect discovery URLs.

## Installation

```bash
pip install trino.oauth2
```

## Quick Start

Check out `example.py` in the repository for complete, runnable examples of all supported flows.

### Basic Usage (Client Credentials)

```python
from trino.oauth2 import OAuth2Client, ClientCredentialsConfig, OidcConfig

# Configure the client
oauth_client = OAuth2Client(
    config=ClientCredentialsConfig(
        client_id="your-client-id",
        client_secret="your-client-secret",
        url_config=OidcConfig(oidc_discovery_url="https://auth.example.com/.well-known/openid-configuration")
    )
)

# Fetch a token
token = oauth_client.token()
print(f"Access Token: {token}")
```

## Configuration

The `OAuth2Client` can be configured with different flow configurations:

- `ClientCredentialsConfig`
- `DeviceCodeConfig`
- `AuthorizationCodeConfig`

It also supports manual URL configuration via `ManualUrlsConfig` if OIDC discovery is not available.

### Secure Token Storage

The library supports secure token storage using `keyrings.cryptfile`. 

To use an encrypted file backend for credentials:

```bash
export PYTHON_KEYRING_BACKEND=keyrings.cryptfile.cryptfile.CryptFileKeyring
export KEYRING_CRYPTFILE_PASSWORD=your_secure_password
```

Or you can pass the password directly (less secure):

```python
oauth_client = OAuth2Client(
    config=...,
    token_storage_password="your_secure_password"
)
```

## Development

### Setup

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements-dev.txt
```

### Running Tests

We use `pytest` for testing. The end-to-end tests run against a Dockerized Hydra instance.

```bash
# Start Hydra
make start-hydra

# Run tests
pytest tests
```

