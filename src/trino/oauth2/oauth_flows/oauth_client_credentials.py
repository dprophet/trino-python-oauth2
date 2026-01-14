"""
this file contains functions related to servermode/client credentials flow.
"""

import urllib
from typing import Optional

import requests

from trino.oauth2 import configs
from trino.oauth2.configs import OAUTHFLOW_GRANT_TYPES, OAuthFlow
from trino.oauth2.models import ClientCredentialsConfig
from trino.oauth2.utils import _oauth_store, proxies
from trino.oauth2.utils._url_helpers import get_token_endpoint_from_oidc


class ClientCredentialsOauth:
    def __init__(
        self,
        config: ClientCredentialsConfig,
        proxy_url: Optional[str] = None
    ) -> None:
        self.config = config
        self.proxy_url = proxy_url

        if self.config.url_config.__class__.__name__ not in (
            'OidcConfig', 'ManualUrlsConfig'
        ):
            raise RuntimeError(
                f"url_config class '{self.config.url_config.__class__.__name__}' "
                "is not allowed."
            )

    def generate_or_refresh_token(self) -> str:
        return self._fetch_and_store_access_token()

    def _get_token_endpoint(self) -> str:
        if self.config.url_config.__class__.__name__ == 'OidcConfig':
            return get_token_endpoint_from_oidc(
                self.config.url_config.oidc_discovery_url
            )
        if self.config.url_config.__class__.__name__ == 'ManualUrlsConfig':
            return self.config.url_config.token_endpoint
        return None

    def _fetch_and_store_access_token(self) -> str:
        """
        This function fetch or generates access token (if there is no valid accesstoken).
        The token will be valid for 2 hours.
        """

        if access_token := _oauth_store.get_active_access_token(
            client_id=self.config.client_id, mode=type(self.config).__name__
        ):
            return access_token

        server_mode_url = self._get_token_endpoint()
        params = {
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "grant_type": OAUTHFLOW_GRANT_TYPES[OAuthFlow.CLIENT_CREDENTIALS],
        }

        if self.config.scope:
            params["scope"] = self.config.scope

        if self.config.audience:
            params["audience"] = []
            for aud in self.config.audience:
                params['audience'].append(aud)

        res = requests.post(
            url=server_mode_url,
            headers={
                "Content-Type": "application/x-www-form-urlencoded;" " charset=UTF-8",
            },
            data=urllib.parse.urlencode(params, doseq=True),
            timeout=configs.REQUEST_TIMEOUT,
            proxies=proxies.get_proxies(proxy_url=self.proxy_url),
        )
        response_json = res.json()
        if "error" in response_json:
            raise RuntimeError(
                f"Fail to generate servermode access token {response_json}"
            )

        access_token = response_json.get("access_token")
        _oauth_store.set_access_token(
            client_id=self.config.client_id,
            mode=type(self.config).__name__,
            access_token=access_token
        )

        return access_token
