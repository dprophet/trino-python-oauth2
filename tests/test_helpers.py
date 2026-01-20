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

import pytest
import jwt
import requests

from configure_hydra import (
    HYDRA_ADMIN_URL
)

def check_hydra_running():
    """Check if Hydra is running and skip test if not."""
    try:
        # Attempt to connect to Hydra's health endpoint or any known endpoint
        response = requests.get(f"{HYDRA_ADMIN_URL}/health/ready", timeout=2)
        if response.status_code != 200:
            pytest.skip(f"Hydra is not running or not ready: {HYDRA_ADMIN_URL}")
    except (requests.RequestException, ImportError):
        pytest.skip(f"Hydra is not running or not accessible: {HYDRA_ADMIN_URL}")

def assert_is_jwt(token: str) -> None:
    """
    Asserts that the token is a well-formed JWT by decoding it without signature verification.
    """
    try:
        # The 'algorithms' parameter is required in pyjwt 2.0+ when decoding without verification.
        jwt.decode(token, options={"verify_signature": False}, algorithms=["RS256"])
    except jwt.InvalidTokenError as e:
        pytest.fail(f"Token is not a valid JWT: {e}")


def assert_is_jwt_with_signature_verification(
    token: str, jwks_uri: str, audience: str = None
) -> None:
    """
    Asserts that the token is a well-formed JWT and verifies its signature
    against Hydra's public keys. Optionally validates the audience.
    """

    try:
        jwks_client = jwt.PyJWKClient(jwks_uri)
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        options = {}
        if audience is None:
            options["verify_aud"] = False

        jwt.decode(
            token,
            key=signing_key.key,
            algorithms=["RS256"],
            audience=audience,
            options=options
        )
    except (jwt.InvalidTokenError, Exception) as e:
        pytest.fail(f"Token validation failed: {e}")


def assert_is_not_jwt_with_signature_verification(token: str, jwks_uri: str) -> None:
    """
    Asserts that the token's signature is invalid by verifying it against Hydra's public keys.
    """
    with pytest.raises(jwt.InvalidSignatureError):
        jwks_client = jwt.PyJWKClient(jwks_uri)
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        jwt.decode(
            token,
            key=signing_key.key,
            algorithms=["RS256"],
        )


def assert_jwt_audiences(token: str, expected_audiences: str) -> None:
    """
    Asserts that the JWT contains all expected audiences in its 'aud' claim.
    expected_audiences: space-delimited string (e.g. 'aud1 aud2')
    Signature is NOT verified.
    """
    try:
        decoded = jwt.decode(token, options={"verify_signature": False}, algorithms=["RS256"])
        aud_claim = decoded.get("aud", [])
        if isinstance(aud_claim, str):
            aud_claim = [aud_claim]
        missing = [aud for aud in expected_audiences if aud not in aud_claim]
        if missing:
            pytest.fail(f"JWT is missing expected audiences: {missing}. Actual: {aud_claim}")
    except (jwt.InvalidTokenError, Exception) as e:
        pytest.fail(f"JWT audience validation failed: {e}")


def assert_jwt_scopes(token: str, expected_scopes: str) -> None:
    """
    Asserts that the JWT contains all expected scopes in its 'scope' claim.
    expected_scopes: space-delimited string (e.g. 'scope1 scope2')
    Signature is NOT verified.
    """
    try:
        expected_scope_list = expected_scopes.split()
        decoded = jwt.decode(token, options={"verify_signature": False}, algorithms=["RS256"])
        scope_claim = decoded.get("scp", "")
        if isinstance(scope_claim, str):
            scopes = scope_claim.split()
        elif isinstance(scope_claim, list):
            scopes = scope_claim
        else:
            scopes = []
        missing = [scope for scope in expected_scope_list if scope not in scopes]
        if missing:
            pytest.fail(f"JWT is missing expected scopes: {missing}. Actual: {scopes}")
    except (jwt.InvalidTokenError, Exception) as e:
        pytest.fail(f"JWT scope validation failed: {e}")
