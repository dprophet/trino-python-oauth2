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

from trino.oauth2.models import DeviceCodeConfig, OidcConfig, ManualUrlsConfig

CLIENT_ID = "fake_client_id"
CLIENT_SECRET = "fake_client_secret"

def test_device_code_instantiation_manual() -> None:
    """
    Test that the DeviceCode class can be instantiated correctly with ManualUrlsConfig.
    """
    url_config = ManualUrlsConfig(
        token_endpoint="https://sso.example.com/token",
        device_authorization_endpoint="https://sso.example.com/device"
    )
    device_code = DeviceCodeConfig(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        url_config=url_config
    )
    assert device_code.client_id == CLIENT_ID
    assert device_code.client_secret == CLIENT_SECRET
    assert device_code.url_config == url_config

def test_device_code_instantiation_oidc() -> None:
    """
    Test that the DeviceCode class can be instantiated correctly with OidcConfig.
    """
    url_config = OidcConfig(
        oidc_discovery_url="https://sso.example.com/.well-known/openid-configuration"
    )
    device_code = DeviceCodeConfig(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        url_config=url_config
    )
    assert device_code.client_id == CLIENT_ID
    assert device_code.client_secret == CLIENT_SECRET
    assert device_code.url_config == url_config
    