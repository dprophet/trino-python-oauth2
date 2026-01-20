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

from configure_hydra import (
    HYDRA_ADMIN_URL,
    HYDRA_OIDC_ENDPOINT,
    AUTHORIZATION_CODE_CLIENT_WITH_SCOPES,
    BAD_CLIENT_CONFIG
)
from hydra_helper import HydraAutoConsent
from test_helpers import check_hydra_running
from trino.oauth2 import OAuth2Client, purge_tokens
from trino.oauth2.models import (
    AuthorizationCodeConfig,
    OidcConfig
)

def test_authorization_code_flow_oidc_bad_scope():
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
            scope=BAD_CLIENT_CONFIG["scope"],
            redirect_uri=AUTHORIZATION_CODE_CLIENT_WITH_SCOPES["redirect_uris"][0],
            url_config=OidcConfig(oidc_discovery_url=HYDRA_OIDC_ENDPOINT),
            automation_callback=automation_callback
        )
    )
    with pytest.raises(ValueError) as excinfo:
        oauth_client.token()

    assert "error: invalid_scope" in str(excinfo.value)


def test_authorization_code_flow_oidc_bad_client_id():
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
            client_id=BAD_CLIENT_CONFIG["client_id"],
            scope=AUTHORIZATION_CODE_CLIENT_WITH_SCOPES["scope"],
            redirect_uri=AUTHORIZATION_CODE_CLIENT_WITH_SCOPES["redirect_uris"][0],
            url_config=OidcConfig(oidc_discovery_url=HYDRA_OIDC_ENDPOINT),
            automation_callback=automation_callback
        )
    )
    with pytest.raises(RuntimeError) as excinfo:
        oauth_client.token()

    assert "error: invalid_client" in str(excinfo.value)


if __name__ == "__main__":
    pytest.main([__file__])
