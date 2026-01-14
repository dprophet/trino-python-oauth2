import requests
from functools import lru_cache

# Use LRU cache to avoid multiple network calls for the same OIDC discovery URL
@lru_cache(maxsize=None)
def _get_oidc_document(oidc_discovery_url: str) -> dict:
    response = requests.get(oidc_discovery_url)
    response.raise_for_status()
    return response.json()

def get_token_endpoint_from_oidc(oidc_discovery_url: str) -> str:
    return _get_oidc_document(oidc_discovery_url)["token_endpoint"]

def get_device_authorization_endpoint_from_oidc(oidc_discovery_url: str) -> str:
    return _get_oidc_document(oidc_discovery_url)["device_authorization_endpoint"]

def get_authorization_endpoint_from_oidc(oidc_discovery_url: str) -> str:
    return _get_oidc_document(oidc_discovery_url)["authorization_endpoint"]

def get_jwks_from_oidc(oidc_discovery_url: str) -> str:
    return _get_oidc_document(oidc_discovery_url)["jwks_uri"]
