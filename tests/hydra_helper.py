from typing import Optional, Union, Dict, List
from urllib.parse import urlparse, parse_qs

import requests


class HydraAutoConsent:
    """
    Automates the Ory Hydra authentication flows by acting as the Administrator.
    """

    def __init__(self, admin_url: str = "http://localhost:4445", user_email: str = "foo@bar.com"):
        self.admin_url = admin_url
        self.user_email = user_email
        # Convert scopes to list if it's a string
        self.session = requests.Session()

    def _get_query_param_s(
            self, url: str, param_name: Optional[str] = None
    ) -> Union[str, Dict[str, List[str]]]:
        """
        Helper to extract query parameters from a URL.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if param_name is None:
            return params
        if param_name not in params:
            raise ValueError(f"Missing '{param_name}' in URL: {url}")
        return params[param_name][0]

    def _get_header_param(self, response: requests.Response, param_name: str) -> Optional[str]:
        """Gets a parameter from the response headers."""
        return response.headers.get(param_name)

    def _get_consent_request_details(self, consent_challenge: str) -> dict:
        """
        Fetches the details of the consent request to see what scopes/audiences were requested.
        """
        url = f"{self.admin_url}/admin/oauth2/auth/requests/consent"
        res = self.session.get(url, params={"consent_challenge": consent_challenge})
        res.raise_for_status()
        return res.json()

    def _accept_device_request(self, device_challenge: str, user_code: str) -> str:
        """Tells Hydra Admin that the user submitted the correct code."""
        url = f"{self.admin_url}/admin/oauth2/auth/requests/device/accept"
        res = self.session.put(
            url,
            params={"device_challenge": device_challenge},
            json={"user_code": user_code}
        )
        res.raise_for_status()
        return res.json()['redirect_to']

    def _accept_login_request(self, login_challenge: str) -> str:
        """Tells Hydra Admin that the user logged in successfully."""
        url = f"{self.admin_url}/admin/oauth2/auth/requests/login/accept"
        res = self.session.put(
            url,
            params={"login_challenge": login_challenge},
            json={
                "subject": self.user_email,
                "remember": True,
                "remember_for": 3600
            }
        )
        res.raise_for_status()
        return res.json()['redirect_to']

    def _accept_consent_request(self, consent_challenge: str) -> str:
        """Tells Hydra Admin that the user consents to the scopes."""

        # Fetch what the client actually requested because we must echo back
        # the scopes and audiences we sent
        details = self._get_consent_request_details(consent_challenge)
        requested_scope = details.get("requested_scope", [])
        requested_audience = details.get(
            "requested_access_token_audience", []
        )

        if requested_scope is not None and len(requested_scope) > 0:
            scopes = requested_scope
        else:
            # Regardless we must send offline scope for hydra to issue tokens
            # in this automated testing flow
            scopes = ["openid", "offline"]

        payload = {
            "grant_scope": scopes,
            "remember": True,
            "remember_for": 3600,
            "session": {
                "id_token": {
                    "email": self.user_email,
                    "name": "Automated Tester"
                }
            }
        }

        if requested_audience is not None and len(requested_audience) > 0:
            payload["grant_access_token_audience"] = requested_audience

        url = f"{self.admin_url}/admin/oauth2/auth/requests/consent/accept"
        res = self.session.put(
            url,
            params={"consent_challenge": consent_challenge},
            json=payload
        )
        res.raise_for_status()
        return res.json()['redirect_to']

    def _perform_login_consent_dance(self, start_url: str) -> str:
        """
        Handles the common Login -> Consent flow.
        Returns the URL provided by Hydra after the Consent step
        (containing consent_verifier).
        """
        # 1. Follow redirect to Login UI
        res = self.session.get(start_url, allow_redirects=False)

        if res.status_code in (302, 303) and 'Location' in res.headers:
            location = self._get_header_param(res, 'Location')
            query_params = self._get_query_param_s(location)
            if 'error' in query_params:
                error = query_params.get('error', [None])[0]
                error_description = query_params.get('error_description', [''])[0]

                if error in ('invalid_state', 'invalid_scope'):
                    raise ValueError(f"error: {error}:{error_description}")
                if error == 'invalid_client':
                    raise RuntimeError(f"error: {error}:{error_description}")
                raise RuntimeError(
                    f"Unknown error. Unexpected redirect to {location} "
                    f"with status {res.status_code}"
                )

        if 'Location' not in res.headers:
            login_ui_url = start_url
        else:
            login_ui_url = res.headers['Location']

        login_challenge = self._get_query_param_s(login_ui_url, "login_challenge")

        # 2. Accept Login
        consent_redirect_url = self._accept_login_request(login_challenge)

        # 3. Follow redirect to Consent UI
        res = self.session.get(consent_redirect_url, allow_redirects=False)
        if 'Location' not in res.headers:
            res.raise_for_status()
            raise ValueError(f"Expected 302 Redirect to Consent UI, got {res.status_code}")

        consent_ui_url = res.headers['Location']
        consent_challenge = self._get_query_param_s(
            consent_ui_url, "consent_challenge"
        )

        # 4. Accept Consent -> Returns URL with consent_verifier
        url_with_verifier = self._accept_consent_request(consent_challenge)

        return url_with_verifier

    def complete_device_flow(self, verification_uri_complete: str) -> None:
        """
        Completes the Device Code flow.
        """
        user_code = self._get_query_param_s(verification_uri_complete, "user_code")

        # Visit verification URI
        res = self.session.get(verification_uri_complete, allow_redirects=False)
        if 'Location' not in res.headers:
            raise ValueError("Expected 302 Redirect to Device UI")

        device_ui_url_full = res.headers['Location']
        device_challenge = self._get_query_param_s(device_ui_url_full, "device_challenge")

        # Accept Device Request -> Returns URL to transition to Login
        verifier_redirect_url = self._accept_device_request(
            device_challenge, user_code
        )

        # Perform Login and Consent
        url_with_verifier = self._perform_login_consent_dance(verifier_redirect_url)

        # Finalize (Device flow redirects to a success page that DOES exist/or doesn't matter)
        self.session.get(url_with_verifier, allow_redirects=True)

    def complete_auth_flow(self, authorization_url: str) -> str:
        """
        Completes the Authorization Code flow and returns the full callback URL.
        """
        # 1. Perform Login and Consent.
        # Returns: .../oauth2/auth?client_id=...&consent_verifier=...
        url_with_verifier = self._perform_login_consent_dance(authorization_url)

        # 2. Exchange the consent_verifier for the final Callback URL.
        # CRITICAL: We set allow_redirects=False.
        # We want to capture the "Location" header (the callback)
        # without actually trying to connect to it (which would fail if no
        # server is running).
        res = self.session.get(url_with_verifier, allow_redirects=False)

        if res.status_code != 303:
            # If Hydra configuration is wrong, it might return 400 or 500 here
            raise ValueError(
                f"Expected 303 Redirect from Hydra, got {res.status_code}. "
                f"Response: {res.text}"
            )

        if 'Location' not in res.headers:
            raise ValueError(
                "Hydra did not return a Location header (Callback URL)."
            )

        # This is the URL: http://localhost:61234/auth/token.callback?code=...
        full_callback_url = res.headers['Location']

        return full_callback_url
