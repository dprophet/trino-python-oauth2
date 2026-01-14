"""
this file contains functions related to authorization code flow.
"""

import logging
import webbrowser
import secrets
import hashlib
import base64
from typing import Optional, Tuple
from urllib.parse import urlencode, parse_qs, urlparse

import requests

from trino.oauth2.configs import (
    OAUTHFLOW_GRANT_TYPES,
    OAuthFlow
)
from trino.oauth2.models import AuthorizationCodeConfig
from trino.oauth2.oauth_flows._refresh_token import refresh_token
from trino.oauth2.utils import _oauth_store, proxies
from trino.oauth2.utils._url_helpers import (
    get_authorization_endpoint_from_oidc,
    get_token_endpoint_from_oidc
)

logger = logging.getLogger(__name__)


class AuthorizationCodeOauth:
    def __init__(
            self,
            config: AuthorizationCodeConfig,
            proxy_url: Optional[str] = None
    ) -> None:
        self.config = config
        self.proxy_url = proxy_url
        self.state = config.state or secrets.token_urlsafe(16)

        # Store the PKCE verifier to use it in the token exchange step
        self.code_verifier: Optional[str] = None

        if self.config.url_config.__class__.__name__ not in (
            'OidcConfig', 'ManualUrlsConfig'
        ):
            raise RuntimeError(
                f"url_config class '{self.config.url_config.__class__.__name__}' "
                "is not allowed."
            )

    def _get_authorization_endpoint(self) -> str:
        if self.config.url_config.__class__.__name__ == 'OidcConfig':
            return get_authorization_endpoint_from_oidc(
                self.config.url_config.oidc_discovery_url
            )
        if self.config.url_config.__class__.__name__ == 'ManualUrlsConfig':
            if self.config.url_config.authorization_endpoint:
                return self.config.url_config.authorization_endpoint
            raise RuntimeError(
                "authorization_endpoint must be provided in ManualUrlsConfig."
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
        initiate the authorization code flow.
        """
        access_token = _oauth_store.get_active_access_token(
            client_id=self.config.client_id, mode=type(self.config).__name__
        )
        if access_token:
            logger.debug("skipping auth. using token in local storage.")
            return access_token

        # Start the interactive flow
        self._start_authorization_flow()

        access_token = _oauth_store.get_active_access_token(
            client_id=self.config.client_id, mode=type(self.config).__name__
        )
        if not access_token:
            raise RuntimeError("Fail to retrieve access token")

        return access_token

    def _generate_pkce_pair(self) -> Tuple[str, str]:
        """
        Generates a PKCE code verifier and code challenge.
        Verifier: Random URL-safe string.
        Challenge: Base64URL-encoded SHA256 hash of the verifier.
        """
        verifier = secrets.token_urlsafe(64)
        digest = hashlib.sha256(verifier.encode('ascii')).digest()
        challenge = base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')
        return verifier, challenge

    def _start_authorization_flow(self) -> bool:
        """
        Constructs the authorization URL (with PKCE if enabled), opens the browser,
        waits for code, and exchanges it for a token.
        """
        auth_endpoint = self._get_authorization_endpoint()

        params = {
            "client_id": self.config.client_id,
            "response_type": "code",
            "redirect_uri": self.config.redirect_uri,
            "state": self.state
        }

        # Add the scope if present
        if self.config.scope:
            params["scope"] = self.config.scope

        if self.config.audience:
            params["audience"] = []
            for aud in self.config.audience:
                params['audience'].append(aud)

        # PKCE Handling
        if getattr(self.config, 'use_pkce', True):
            verifier, challenge = self._generate_pkce_pair()
            self.code_verifier = verifier
            params["code_challenge"] = challenge
            params["code_challenge_method"] = "S256"

        authorization_url = f"{auth_endpoint}?{urlencode(params, doseq=True)}"

        if self.config.automation_callback:
            # Automation mode: callback visits the URL and returns full redirect URL
            final_redirect_url = self.config.automation_callback(authorization_url)
            auth_code = self._extract_code_from_input(final_redirect_url)
        else:
            self._open_login_window(authorization_url)

            prompt_msg = (
                "\nStandard Authorization Code Flow:\n"
                "1. The browser should have opened to the login page.\n"
                "2. Please log in and authorize the application.\n"
                "3. You will be redirected to a URL containing a 'code' parameter.\n"
                "4. Copy the value of the 'code' parameter (or the full URL) "
                "and paste it below.\n\n"
                "Enter Authorization Code: "
            )

            try:
                user_input = raw_input(prompt_msg)  # type: ignore
            except NameError:
                user_input = input(prompt_msg)

            auth_code = self._extract_code_from_input(user_input)

        token_stored = self._exchange_code_for_token(auth_code)

        if not token_stored:
            raise RuntimeError("No token data was received via authorization flow.")

        return True

    def _extract_code_from_input(self, user_input: str) -> str:
        """Helper to parse code if user pastes full URL"""
        if "code=" in user_input:
            try:
                parsed = urlparse(user_input)
                # handle cases where user pasted just query string or full url
                if not parsed.query and "?" in user_input:
                    qs = parse_qs(user_input.split('?')[1])
                elif parsed.query:
                    qs = parse_qs(parsed.query)
                else:
                    qs = parse_qs(user_input)

                if 'code' in qs:
                    return qs['code'][0]
            except Exception:
                pass
        return user_input.strip()

    def _open_login_window(self, url: str):
        try:
            webbrowser.open(url)
        except Exception as e:  # type: ignore
            logger.exception("Error opening browser. %s", e)

    def _exchange_code_for_token(self, code: str) -> bool:
        get_token_url = self._get_token_endpoint()

        params: dict[str, str] = {
            "grant_type": OAUTHFLOW_GRANT_TYPES[OAuthFlow.AUTH_CODE_PKCE],
            "client_id": self.config.client_id,
            "code": code,
            "redirect_uri": self.config.redirect_uri,
        }

        if self.config.client_secret:
            params["client_secret"] = self.config.client_secret

        # Add the Code Verifier if PKCE was used
        if self.code_verifier:
            params["code_verifier"] = self.code_verifier

        res = requests.post(
            get_token_url,
            data=params,
            timeout=5,
            proxies=proxies.get_proxies(proxy_url=self.proxy_url),
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        if res.status_code < 200 or res.status_code > 299:
            error = res.json()["error_description"]
            raise RuntimeError(error)

        if "access_token" in res.json():
            access_token = res.json().get("access_token")
            refresh_token = res.json().get("refresh_token")
            _oauth_store.set_access_and_refresh_tokens(
                self.config.client_id, type(self.config).__name__, access_token, refresh_token
            )

            return True

        return False
