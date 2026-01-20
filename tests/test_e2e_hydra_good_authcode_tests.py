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

import base64

import pytest

from configure_hydra import (
    HYDRA_ADMIN_URL,
    HYDRA_OIDC_ENDPOINT,
    AUTHORIZATION_CODE_CLIENT_WITH_SCOPES,
    AUTHORIZATION_CODE_CLIENT
)
from hydra_helper import HydraAutoConsent
from test_helpers import (
    assert_is_jwt_with_signature_verification,
    assert_is_not_jwt_with_signature_verification,
    check_hydra_running
)
from trino.oauth2 import OAuth2Client, purge_tokens, get_jwks_from_oidc
from trino.oauth2.models import (
    AuthorizationCodeConfig,
    OidcConfig
)


# [NEW] Test for Authorization Code Flow
def test_authorization_code_flow_oidc_with_scopes():
    """Tests the authorization code flow against the Hydra test environment."""
    check_hydra_running()

    # 1. Purge existing tokens
    purge_tokens(
        AUTHORIZATION_CODE_CLIENT_WITH_SCOPES["client_id"],
        AuthorizationCodeConfig
    )

    # 2. Initialize Helper
    hydra_automator = HydraAutoConsent(admin_url=HYDRA_ADMIN_URL)

    # 3. Define the automation behavior
    flow_result: dict[str, str | None] = {"full_redirect_url": None}

    def automation_callback(url: str) -> str:
        result_url = hydra_automator.complete_auth_flow(url)
        flow_result["full_redirect_url"] = result_url
        return result_url

    # 4. Initialize Client
    oauth_client = OAuth2Client(
        config=AuthorizationCodeConfig(
            client_id=AUTHORIZATION_CODE_CLIENT_WITH_SCOPES["client_id"],
            scope=AUTHORIZATION_CODE_CLIENT_WITH_SCOPES["scope"],
            redirect_uri=AUTHORIZATION_CODE_CLIENT_WITH_SCOPES["redirect_uris"][0],
            url_config=OidcConfig(oidc_discovery_url=HYDRA_OIDC_ENDPOINT),
            automation_callback=automation_callback
        )
    )

    # 5. Execute
    token = oauth_client.token()

    good_token = token
    # Corrupt the token by tampering with the signature
    header, payload, _ = token.rsplit('.', 2)
    bad_signature = base64.urlsafe_b64encode(b'badsignature').decode()
    bad_token = f"{header}.{payload}.{bad_signature}"

    # 6. Verify
    assert isinstance(good_token, str)
    assert_is_not_jwt_with_signature_verification(
        bad_token, get_jwks_from_oidc(HYDRA_OIDC_ENDPOINT)
    )

    assert_is_jwt_with_signature_verification(
        good_token, get_jwks_from_oidc(HYDRA_OIDC_ENDPOINT)
    )
    print("Authorization code flow oidc with scopes completed successfully.")


def test_authorization_code_flow_oidc_no_scopes():
    """Tests the authorization code flow against the Hydra test environment."""
    check_hydra_running()

    # 1. Purge existing tokens
    purge_tokens(AUTHORIZATION_CODE_CLIENT["client_id"], AuthorizationCodeConfig)

    # 2. Initialize Helper
    hydra_automator = HydraAutoConsent(admin_url=HYDRA_ADMIN_URL)

    # 3. Define the automation behavior
    flow_result: dict[str, str | None] = {"full_redirect_url": None}

    def automation_callback(url: str) -> str:
        result_url = hydra_automator.complete_auth_flow(url)
        flow_result["full_redirect_url"] = result_url
        return result_url

    # 4. Initialize Client
    oauth_client = OAuth2Client(
        config=AuthorizationCodeConfig(
            client_id=AUTHORIZATION_CODE_CLIENT["client_id"],
            client_secret=AUTHORIZATION_CODE_CLIENT["client_secret"],
            redirect_uri=AUTHORIZATION_CODE_CLIENT["redirect_uris"][0],
            url_config=OidcConfig(oidc_discovery_url=HYDRA_OIDC_ENDPOINT),
            automation_callback=automation_callback
        )
    )

    # 5. Execute
    token = oauth_client.token()

    # 6. Verify
    assert isinstance(token, str)
    assert_is_jwt_with_signature_verification(
        token, get_jwks_from_oidc(HYDRA_OIDC_ENDPOINT)
    )
    print("Authorization code flow oidc no scopes completed successfully.")



if __name__ == "__main__":
    pytest.main([__file__])
