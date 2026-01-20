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

from trino.oauth2 import OAuth2Client
from trino.oauth2.models import DeviceCodeConfig, ManualUrlsConfig

CLIENT_ID = "fake_client_id"
CLIENT_SECRET = "fake_client_secret"

def test_oauth_client() -> None:

    url_config = ManualUrlsConfig(
        token_endpoint="https://sso.example.com/token",
        device_authorization_endpoint="https://sso.example.com/device"
    )

    oauth_client = OAuth2Client(
        config=DeviceCodeConfig(client_id="", client_secret="", url_config=url_config)
    )

    assert isinstance(oauth_client, OAuth2Client)
    attr = getattr(oauth_client, "token")
    assert callable(attr)
