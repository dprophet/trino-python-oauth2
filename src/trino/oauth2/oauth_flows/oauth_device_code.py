"""
this file contains functions related to device code flow (aka user mode).
"""

import logging
import time
import webbrowser
from dataclasses import dataclass, fields
from typing import Optional
from urllib.parse import urlencode

import requests

from trino.oauth2 import configs
from trino.oauth2.configs import (
    OAUTHFLOW_GRANT_TYPES,
    OAuthFlow
)
from trino.oauth2.models import DeviceCodeConfig
from trino.oauth2.oauth_flows._refresh_token import refresh_token
from trino.oauth2.utils import _oauth_store, proxies
from trino.oauth2.utils._url_helpers import (
    get_device_authorization_endpoint_from_oidc,
    get_token_endpoint_from_oidc
)

logger = logging.getLogger(__name__)


@dataclass
class OauthDeviceFlowResponse:
    verification_uri_complete: str
    user_code: str
    device_code: str
    interval: int
    verification_uri: str
    expires_in: int


class DeviceCodeOauth:
    def __init__(
        self,
        config: DeviceCodeConfig,
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

    def _get_device_authorization_endpoint(self) -> str:
        if self.config.url_config.__class__.__name__ == 'OidcConfig':
            return get_device_authorization_endpoint_from_oidc(
                self.config.url_config.oidc_discovery_url
            )
        if self.config.url_config.__class__.__name__ == 'ManualUrlsConfig':
            if self.config.url_config.device_authorization_endpoint:
                return self.config.url_config.device_authorization_endpoint
            raise RuntimeError(
                "device_authorization_endpoint must be provided in ManualUrlsConfig."
            )
        return None

    def _get_token_endpoint(self) -> str:
        if self.config.url_config.__class__.__name__ == 'OidcConfig':
            return get_token_endpoint_from_oidc(
                self.config.url_config.oidc_discovery_url
            )
        if self.config.url_config.__class__.__name__ == 'ManualUrlsConfig':
            return self.config.url_config.token_endpoint
        return None

    def generate_or_refresh_token(self) -> str:
        try:
            access_token = refresh_token(
                config=self.config,
                refresh_url=self._get_token_endpoint(),
                proxy_url=self.proxy_url
            )
        except Exception as e:
            logger.debug(
                f"Failed to update the access token. \
                A new access token must be obtained before API calls can succeed. \
                Error: {e}"
            )
            _oauth_store.purge_tokens(self.config.client_id, self.config)
            access_token = self._fetch_and_store_access_token()

        return access_token

    def _fetch_and_store_access_token(self) -> str:
        """
        If a valid token is not retrieved from local storage,
        start_device_code_auth will direct the user to authenticate via a UI.
        If poll_for_token is True, then once the user has authenticated in the UI,
        start_device_code_auth wil detect the auth has
        been completed and will fetch the token. If poll_for_token is False,
        the user will be prompted to hit Enter after authenticating,
        and start_device_code_auth will then fetch the token.
        """

        access_token = _oauth_store.get_active_access_token(
            client_id=self.config.client_id, mode=type(self.config).__name__
        )
        if access_token:
            logger.debug("skipping auth. using token in local storage.")
            return access_token
        if self.config.poll_for_token:
            self._start_device_code_auth_poll()
        else:
            self._start_device_code_auth_no_poll()
        access_token = _oauth_store.get_active_access_token(
            client_id=self.config.client_id, mode=type(self.config).__name__
        )
        if not access_token:
            raise RuntimeError("Fail to retrieve access token")

        return access_token

    def _start_device_code_auth_no_poll(self) -> bool:
        """
        This method is used when poll_for_token is False.
        The user will be prompted to hit Enter after authenticating,
        and start_device_code_auth will then fetch the token.
        
        THIS SHOULD ONLY BE USED FOR TESTING PURPOSES.
        """
        device_flow = self._start_device_flow()

        if self.config.automation_callback:
            self.config.automation_callback(device_flow.verification_uri_complete)
        else:
            self._open_login_window(device_flow=device_flow)

            prompt_msg = (
                "\nConfirm authorization code shown in UI matches: "
                f"{device_flow.user_code}. If so, authenticate and press ENTER once done...\n"
            )
            try:
                # Script waits for user to hit Enter.
                # User hits enter only once they have authenticated with oauth.
                raw_input(prompt_msg)  # type: ignore
            except NameError:
                input(prompt_msg)

        token_stored = self._fetch_and_store_device_flow_token(
            device_code=device_flow.device_code,
        )
        if not token_stored:
            raise RuntimeError("No token data was received via device flow.")

        return True

    def _start_device_code_auth_poll(self) -> bool:
        device_flow = self._start_device_flow()

        if self.config.automation_callback:
            # This is for automated testing purposes only (no user interaction needed).
            self.config.automation_callback(device_flow.verification_uri_complete)
        else:
            self._open_login_window(device_flow=device_flow)

            msg = (
                "If browser did not open, copy this link into your browser "
                f"and follow instructions. {device_flow.verification_uri_complete}\n\n"
                "Confirm authorization code shown in UI matches: "
                f"{device_flow.user_code}. If not, do not authenticate and abort."
            )
            print(msg)

        return self._poll_for_device_flow_token(device_flow=device_flow)

    def _start_device_flow(self) -> OauthDeviceFlowResponse:
        device_flow_auth_url = self._get_device_authorization_endpoint()
        params: dict[str, str] = {
            "client_id": self.config.client_id,
        }
        if self.config.client_secret:
            params["client_secret"] = self.config.client_secret

        if self.config.scope:
            params["scope"] = self.config.scope

        if self.config.audience:
            params["audience"] = []
            for aud in self.config.audience:
                params['audience'].append(aud)

        res = self._send_post(url=device_flow_auth_url, data=params)
        if res.status_code < 200 or res.status_code > 299:
            error = res.json()["error_description"]
            raise RuntimeError(error)

        response_json = res.json()
        expected_fields = [f.name for f in fields(OauthDeviceFlowResponse)]
        filtered_response = {k: v for k, v in response_json.items() if k in expected_fields}

        device_flow = OauthDeviceFlowResponse(**filtered_response)

        return device_flow

    def _open_login_window(self, device_flow: OauthDeviceFlowResponse):
        try:
            webbrowser.open(device_flow.verification_uri_complete)
        except Exception as e:  # type: ignore
            logger.exception("Error opening browser. %s", e)

    def _poll_for_device_flow_token(self, device_flow: OauthDeviceFlowResponse) -> bool:
        i = 0
        while i < device_flow.expires_in / device_flow.interval:
            if i % device_flow.interval == 0:
                logger.info("Polling for token...")
            time.sleep(device_flow.interval)
            token_stored = self._fetch_and_store_device_flow_token(
                device_code=device_flow.device_code
            )
            if token_stored:
                logger.info(
                    "Authentication has completed, the token has been retrieved."
                )
                return True
            i += 1
        logger.warning("\nDevice code has expired, polling has stopped.\n")
        return False

    def _fetch_and_store_device_flow_token(self, device_code: str) -> bool:
        get_token_url = self._get_token_endpoint()

        params: dict[str, str] = {
            "client_id": self.config.client_id,
            "device_code": device_code,
            "grant_type": OAUTHFLOW_GRANT_TYPES[OAuthFlow.DEVICE_CODE],
        }
        if self.config.client_secret:
            params["client_secret"] = self.config.client_secret

        try:
            res = requests.post(
                get_token_url,
                data=params,
                timeout=5,
                proxies=proxies.get_proxies(proxy_url=self.proxy_url),
            )
            if "access_token" in res.json():
                access_token = res.json().get("access_token")
                refresh_token = res.json().get("refresh_token")
                _oauth_store.set_access_and_refresh_tokens(
                    self.config.client_id, type(self.config).__name__, access_token, refresh_token
                )
                return True
        except Exception as e:  # type: ignore
            logger.exception(
                "Request to oauth for access token failed with exception: %s", e
            )
            return False
        return False

    def _send_post(self, url: str, data: dict[str, str]) -> requests.Response:
        res = requests.post(
            url,
            headers={
                "Content-Type": "application/x-www-form-urlencoded;" " charset=UTF-8",
            },
            data=urlencode(data, doseq=True),
            timeout=configs.REQUEST_TIMEOUT,
            proxies=proxies.get_proxies(proxy_url=self.proxy_url),
        )
        return res
