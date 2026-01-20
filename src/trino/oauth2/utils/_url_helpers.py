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
