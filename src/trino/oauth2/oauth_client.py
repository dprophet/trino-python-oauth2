from typing import Optional, Union

from trino.oauth2 import configs
from trino.oauth2.models import (
    ClientCredentialsConfig,
    DeviceCodeConfig,
    AuthorizationCodeConfig
)
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
    ) -> None:
        """Base Config that removes as much complexity from user as possible"""
        self.config = config
        self.proxy_url = proxy_url
        self.valid_min_duration_threshold = valid_min_duration_threshold
        self.oauth_flow_client = self._initiate_oauth_flow_client()

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
