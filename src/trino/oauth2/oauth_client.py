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

from typing import Optional, Union

from trino.oauth2 import configs
from trino.oauth2.models import (
    ClientCredentialsConfig,
    DeviceCodeConfig,
    AuthorizationCodeConfig
)
import os
from trino.oauth2.oauth_flows.oauth_device_code import DeviceCodeOauth
from trino.oauth2.oauth_flows.oauth_client_credentials import ClientCredentialsOauth
from trino.oauth2.oauth_flows.oauth_authorization_mode import AuthorizationCodeOauth
from trino.oauth2.utils import _oauth_store


class OAuth2Client:
    """
        The OAuth2Client is the main entry point for the OAuth2 library. It is
        used to generate or refresh an access token.
        The Client offers three constuctor options:
            1. A Simplified Constructor: Enviroment and all other configs are
            assumed. Valid for most external users.
            2. A Full Constructor: Enviroment and all other configs are
            provided. Valid for internal users.
            3. A Custom Routing Constructor: Routing configs are provided. For
            users with unique routing requirment, such as reverse proxing.
    """
    url_config: Union[ClientCredentialsConfig, DeviceCodeConfig]
    valid_min_duration_threshold: int
    proxy_url: Optional[str]

    def __init__(
        self,
        config: Union[ClientCredentialsConfig, DeviceCodeConfig, AuthorizationCodeConfig],
        valid_min_duration_threshold: int = configs.VALID_MIN_DURATION_THRESHOLD,
        proxy_url: Optional[str] = None,
        token_storage_password: Optional[str] = None,
    ) -> None:
        """Base Config that removes as much complexity from user as possible"""
        self.config = config
        self.proxy_url = proxy_url
        self.valid_min_duration_threshold = valid_min_duration_threshold
        self.oauth_flow_client = self._initiate_oauth_flow_client()
        current_backend = os.environ.get("PYTHON_KEYRING_BACKEND")
        if not current_backend or current_backend == "keyrings.cryptfile.cryptfile.CryptFileKeyring":
            self.configure_cryptfile_from_env(token_storage_password=token_storage_password)

    def _initiate_oauth_flow_client(
        self,
    ) -> Union[ClientCredentialsOauth, DeviceCodeOauth, AuthorizationCodeOauth]:
        if isinstance(self.config, ClientCredentialsConfig):
            return ClientCredentialsOauth(
                config=self.config,
                proxy_url=self.proxy_url,
            )
        if isinstance(self.config, DeviceCodeConfig):
            return DeviceCodeOauth(
                config=self.config,
                proxy_url=self.proxy_url,
            )
        if isinstance(self.config, AuthorizationCodeConfig):
            return AuthorizationCodeOauth(
                config=self.config,
                proxy_url=self.proxy_url,
            )
        raise ValueError(f"Invalid Oauth Mode {type(self.config).__name__}")

    def token(
        self,
    ) -> str:
        access_token = _oauth_store.get_active_access_token(
            client_id=self.config.client_id,
            mode=type(self.config).__name__,
            valid_min_duration_threshold=self.valid_min_duration_threshold,
        )
        if access_token:
            return access_token

        return self.oauth_flow_client.generate_or_refresh_token()

    def configure_cryptfile_from_env(
            self,
            env_var: str = "KEYRING_CRYPTFILE_PASSWORD",
            token_storage_password: Optional[str] = None,
    ) -> None:
        # this must be lazily loaded only when this class is instantiated, not imported
        import keyring
        from keyrings.cryptfile.cryptfile import CryptFileKeyring

        pw = os.environ.get(env_var)
        if not pw:
            pw = token_storage_password

        if not pw:
            raise RuntimeError(f"{env_var} is not set and no token_storage_password provided")

        kr = CryptFileKeyring()
        kr.keyring_key = pw
        keyring.set_keyring(kr)
