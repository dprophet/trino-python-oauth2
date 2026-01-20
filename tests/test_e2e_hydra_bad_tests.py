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
import pytest

from configure_hydra import (
    HYDRA_ADMIN_URL,
    HYDRA_OIDC_ENDPOINT,
    CLIENT_CREDENTIALS_CLIENT,
    DEVICE_CODE_CLIENT_NO_SECRETS_WITH_SCOPES,
    BAD_CLIENT_CONFIG
)
from hydra_helper import HydraAutoConsent
from test_helpers import check_hydra_running
from trino.oauth2 import OAuth2Client, purge_tokens
from trino.oauth2.models import DeviceCodeConfig, ClientCredentialsConfig, OidcConfig

def test_list_directory():
    print("test_list_directory: Current working directory:", os.getcwd())
    print("test_list_directory: Current directory contents:", os.listdir('.'))
    print("test_list_directory: tests directory contents:", os.listdir('./tests'))

def test_client_credentials_flow_bad_client_id():
    # A bad client ID is one that doesn't exist. No need to purge.
    check_hydra_running()

    oauth_client = OAuth2Client(
        config=ClientCredentialsConfig(
            client_id=BAD_CLIENT_CONFIG["client_id"],  # Intentionally bad
            client_secret=CLIENT_CREDENTIALS_CLIENT["client_secret"],
            url_config=OidcConfig(oidc_discovery_url=HYDRA_OIDC_ENDPOINT)
        )
    )
    with pytest.raises(RuntimeError) as excinfo:
        oauth_client.token()

    assert "'error': 'invalid_client'" in str(excinfo.value)


def test_client_credentials_flow_bad_secret():
    check_hydra_running()

    purge_tokens(CLIENT_CREDENTIALS_CLIENT["client_id"], ClientCredentialsConfig)

    oauth_client = OAuth2Client(
        config=ClientCredentialsConfig(
            client_id=CLIENT_CREDENTIALS_CLIENT["client_id"],
            client_secret=BAD_CLIENT_CONFIG["client_secret"],  # Intentionally bad
            url_config=OidcConfig(oidc_discovery_url=HYDRA_OIDC_ENDPOINT)
        )
    )
    with pytest.raises(RuntimeError) as excinfo:
        oauth_client.token()

    assert "'error': 'invalid_client'" in str(excinfo.value)


def test_client_credentials_flow_bad_scope():
    check_hydra_running()

    purge_tokens(CLIENT_CREDENTIALS_CLIENT["client_id"], ClientCredentialsConfig)

    oauth_client = OAuth2Client(
        config=ClientCredentialsConfig(
            client_id=CLIENT_CREDENTIALS_CLIENT["client_id"],
            client_secret=CLIENT_CREDENTIALS_CLIENT["client_secret"],
            scope=BAD_CLIENT_CONFIG["scope"],  # Intentionally bad
            url_config=OidcConfig(oidc_discovery_url=HYDRA_OIDC_ENDPOINT)
        )
    )
    with pytest.raises(RuntimeError) as excinfo:
        oauth_client.token()

    assert "'error': 'invalid_scope'" in str(excinfo.value)


def test_device_code_flow_bad_scope():
    """Tests the device code flow against the Hydra test environment."""
    check_hydra_running()

    # Purge existing tokens
    purge_tokens(DEVICE_CODE_CLIENT_NO_SECRETS_WITH_SCOPES["client_id"], DeviceCodeConfig)

    # Initialize the helper class
    hydra_automator = HydraAutoConsent(admin_url=HYDRA_ADMIN_URL)

    oauth_client = OAuth2Client(
        config=DeviceCodeConfig(
            client_id=DEVICE_CODE_CLIENT_NO_SECRETS_WITH_SCOPES["client_id"],
            scope=BAD_CLIENT_CONFIG["scope"],  # Intentionally bad
            url_config=OidcConfig(oidc_discovery_url=HYDRA_OIDC_ENDPOINT),
            poll_for_token=True,
            # automation_callback is purely for simulating the user interaction
            automation_callback=hydra_automator.complete_device_flow
        )
    )
    with pytest.raises(RuntimeError) as excinfo:
        oauth_client.token()

    assert "The requested scope is invalid" in str(excinfo.value)


if __name__ == "__main__":
    pytest.main([__file__])
