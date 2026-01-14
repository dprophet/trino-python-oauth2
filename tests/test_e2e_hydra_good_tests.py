import pytest

from configure_hydra import (
    HYDRA_ADMIN_URL,
    TOKEN_ENDPOINT,
    DEVICE_AUTH_ENDPOINT,
    HYDRA_OIDC_ENDPOINT,
    CLIENT_CREDENTIALS_CLIENT,
    CLIENT_CREDENTIALS_WITH_AUDIENCE,
    DEVICE_CODE_CLIENT_WITH_SECRETS,
    DEVICE_CODE_CLIENT_NO_SECRETS_WITH_SCOPES,
    DEVICE_CODE_CLIENT_NO_SECRETS_WITH_SCOPES_AUDIENCE,
    AUTHORIZATION_CODE_CLIENT,
    AUTHORIZATION_CODE_CLIENT_WITH_SCOPES
)
from hydra_helper import HydraAutoConsent
from test_helpers import (
    assert_is_jwt_with_signature_verification,
    assert_jwt_audiences,
    assert_jwt_scopes,
    check_hydra_running
)
from trino.oauth2 import OAuth2Client, purge_tokens, get_jwks_from_oidc
from trino.oauth2.models import (
    DeviceCodeConfig,
    ClientCredentialsConfig,
    AuthorizationCodeConfig,
    ManualUrlsConfig,
    OidcConfig
)


def test_client_credentials_flow_manual():
    check_hydra_running()

    purge_tokens(CLIENT_CREDENTIALS_CLIENT["client_id"], ClientCredentialsConfig)
    oauth_client = OAuth2Client(
        config=ClientCredentialsConfig(
            client_id=CLIENT_CREDENTIALS_CLIENT["client_id"],
            client_secret=CLIENT_CREDENTIALS_CLIENT["client_secret"],
            url_config=ManualUrlsConfig(token_endpoint=TOKEN_ENDPOINT)
        )
    )
    token = oauth_client.token()
    assert isinstance(token, str)
    assert_is_jwt_with_signature_verification(token, get_jwks_from_oidc(HYDRA_OIDC_ENDPOINT))
    print("Hydra Client Credentials manual completed successfully.")


def test_client_credentials_flow_oidc():
    check_hydra_running()

    purge_tokens(CLIENT_CREDENTIALS_CLIENT["client_id"], ClientCredentialsConfig)
    oauth_client = OAuth2Client(
        config=ClientCredentialsConfig(
            client_id=CLIENT_CREDENTIALS_CLIENT["client_id"],
            client_secret=CLIENT_CREDENTIALS_CLIENT["client_secret"],
            url_config=OidcConfig(oidc_discovery_url=HYDRA_OIDC_ENDPOINT)
        )
    )
    token = oauth_client.token()
    assert isinstance(token, str)
    assert_is_jwt_with_signature_verification(token, get_jwks_from_oidc(HYDRA_OIDC_ENDPOINT))
    print("Hydra Client Credentials oidc completed successfully.")


def test_client_credentials_flow_w_scope():
    check_hydra_running()

    purge_tokens(CLIENT_CREDENTIALS_CLIENT["client_id"], ClientCredentialsConfig)
    oauth_client = OAuth2Client(
        config=ClientCredentialsConfig(
            client_id=CLIENT_CREDENTIALS_CLIENT["client_id"],
            client_secret=CLIENT_CREDENTIALS_CLIENT["client_secret"],
            scope=CLIENT_CREDENTIALS_CLIENT["scope"],
            url_config=OidcConfig(oidc_discovery_url=HYDRA_OIDC_ENDPOINT)
        )
    )
    token = oauth_client.token()
    assert isinstance(token, str)
    assert_is_jwt_with_signature_verification(token, get_jwks_from_oidc(HYDRA_OIDC_ENDPOINT))
    assert_jwt_scopes(token, CLIENT_CREDENTIALS_CLIENT["scope"])
    print("Hydra Client Credentials flow manual completed successfully.")

def test_client_credentials_flow_w_audience():
    check_hydra_running()

    purge_tokens(CLIENT_CREDENTIALS_WITH_AUDIENCE["client_id"], ClientCredentialsConfig)
    oauth_client = OAuth2Client(
        config=ClientCredentialsConfig(
            client_id=CLIENT_CREDENTIALS_WITH_AUDIENCE["client_id"],
            client_secret=CLIENT_CREDENTIALS_WITH_AUDIENCE["client_secret"],
            audience=CLIENT_CREDENTIALS_WITH_AUDIENCE["audience"],
            url_config=OidcConfig(oidc_discovery_url=HYDRA_OIDC_ENDPOINT)
        )
    )
    token = oauth_client.token()
    assert isinstance(token, str)
    assert_is_jwt_with_signature_verification(token, get_jwks_from_oidc(HYDRA_OIDC_ENDPOINT))
    assert_jwt_audiences(token, CLIENT_CREDENTIALS_WITH_AUDIENCE["audience"])
    print("Hydra Client Credentials flow manual completed successfully.")


def test_device_code_flow_manual():
    check_hydra_running()

    purge_tokens(DEVICE_CODE_CLIENT_WITH_SECRETS["client_id"], DeviceCodeConfig)
    hydra_automator = HydraAutoConsent(admin_url=HYDRA_ADMIN_URL)
    oauth_client = OAuth2Client(
        config=DeviceCodeConfig(
            client_id=DEVICE_CODE_CLIENT_WITH_SECRETS["client_id"],
            client_secret=DEVICE_CODE_CLIENT_WITH_SECRETS["client_secret"],
            scope=DEVICE_CODE_CLIENT_WITH_SECRETS["scope"],
            url_config=ManualUrlsConfig(
                token_endpoint=TOKEN_ENDPOINT,
                device_authorization_endpoint=DEVICE_AUTH_ENDPOINT
            ),
            poll_for_token=True,
            # automation_callback is purely for simulating the user interaction
            automation_callback=hydra_automator.complete_device_flow
        )
    )
    token = oauth_client.token()
    assert isinstance(token, str)
    assert_is_jwt_with_signature_verification(token, get_jwks_from_oidc(HYDRA_OIDC_ENDPOINT))
    print("Hydra Device flow manual completed successfully.")


def test_device_code_flow_oidc():
    check_hydra_running()

    purge_tokens(DEVICE_CODE_CLIENT_WITH_SECRETS["client_id"], DeviceCodeConfig)
    hydra_automator = HydraAutoConsent(admin_url=HYDRA_ADMIN_URL)
    oauth_client = OAuth2Client(
        config=DeviceCodeConfig(
            client_id=DEVICE_CODE_CLIENT_WITH_SECRETS["client_id"],
            client_secret=DEVICE_CODE_CLIENT_WITH_SECRETS["client_secret"],
            scope=DEVICE_CODE_CLIENT_WITH_SECRETS["scope"],
            url_config=OidcConfig(oidc_discovery_url=HYDRA_OIDC_ENDPOINT),
            poll_for_token=True,
            # automation_callback is purely for simulating the user interaction
            automation_callback=hydra_automator.complete_device_flow
        )
    )
    token = oauth_client.token()
    assert isinstance(token, str)
    assert_is_jwt_with_signature_verification(token, get_jwks_from_oidc(HYDRA_OIDC_ENDPOINT))
    print("Hydra Device flow OIDC completed successfully.")


def test_device_code_flow_no_secrets():
    check_hydra_running()

    purge_tokens(DEVICE_CODE_CLIENT_NO_SECRETS_WITH_SCOPES["client_id"], DeviceCodeConfig)
    hydra_automator = HydraAutoConsent(admin_url=HYDRA_ADMIN_URL)
    oauth_client = OAuth2Client(
        config=DeviceCodeConfig(
            client_id=DEVICE_CODE_CLIENT_NO_SECRETS_WITH_SCOPES["client_id"],
            scope=DEVICE_CODE_CLIENT_NO_SECRETS_WITH_SCOPES["scope"],
            url_config=OidcConfig(oidc_discovery_url=HYDRA_OIDC_ENDPOINT),
            poll_for_token=True,
            # automation_callback is purely for simulating the user interaction
            automation_callback=hydra_automator.complete_device_flow
        )
    )
    token = oauth_client.token()
    assert isinstance(token, str)
    assert_is_jwt_with_signature_verification(token, get_jwks_from_oidc(HYDRA_OIDC_ENDPOINT))
    print("Hydra device flow no secrets completed successfully.")

def test_device_code_flow_no_secrets_scopes_audience():
    check_hydra_running()

    purge_tokens(DEVICE_CODE_CLIENT_NO_SECRETS_WITH_SCOPES_AUDIENCE["client_id"], DeviceCodeConfig)
    hydra_automator = HydraAutoConsent(admin_url=HYDRA_ADMIN_URL)

    oauth_client = OAuth2Client(
        config=DeviceCodeConfig(
            client_id=DEVICE_CODE_CLIENT_NO_SECRETS_WITH_SCOPES_AUDIENCE["client_id"],
            scope=DEVICE_CODE_CLIENT_NO_SECRETS_WITH_SCOPES_AUDIENCE["scope"],
            audience=DEVICE_CODE_CLIENT_NO_SECRETS_WITH_SCOPES_AUDIENCE["audience"],
            url_config=OidcConfig(oidc_discovery_url=HYDRA_OIDC_ENDPOINT),
            poll_for_token=True,
            # automation_callback is purely for simulating the user interaction
            automation_callback=hydra_automator.complete_device_flow
        )
    )
    token = oauth_client.token()
    assert isinstance(token, str)
    assert_is_jwt_with_signature_verification(token, get_jwks_from_oidc(HYDRA_OIDC_ENDPOINT))
    assert_jwt_scopes(token, DEVICE_CODE_CLIENT_NO_SECRETS_WITH_SCOPES_AUDIENCE["scope"])
    assert_jwt_audiences(token, DEVICE_CODE_CLIENT_NO_SECRETS_WITH_SCOPES_AUDIENCE["audience"])
    print("Hydra device flow no secrets completed successfully.")

# [NEW] Test for Authorization Code Flow
def test_authorization_code_flow_oidc():
    """Tests the authorization code flow against the Hydra test environment."""
    check_hydra_running()

    # 1. Purge existing tokens
    purge_tokens(AUTHORIZATION_CODE_CLIENT["client_id"], AuthorizationCodeConfig)

    # 2. Initialize Helper
    hydra_automator = HydraAutoConsent(admin_url=HYDRA_ADMIN_URL)

    # 3. Define the automation behavior
    # We use a mutable container to capture the callback URL returned by Hydra
    flow_result: dict[str, str | None] = {"full_redirect_url": None}

    def automation_callback(url: str) -> str:
        # This function mimics the user opening the browser and logging in.
        # It returns the full redirect URL (e.g., localhost:5555/callback?code=...)
        # which our oauth_authorization_mode.py logic will then parse.
        result_url = hydra_automator.complete_auth_flow(url)
        flow_result["full_redirect_url"] = result_url
        return result_url

    # 4. Initialize Client
    oauth_client = OAuth2Client(
        config=AuthorizationCodeConfig(
            client_id=AUTHORIZATION_CODE_CLIENT["client_id"],
            client_secret=AUTHORIZATION_CODE_CLIENT["client_secret"],
            scope="openid offline",
            redirect_uri=AUTHORIZATION_CODE_CLIENT["redirect_uris"][0],
            url_config=OidcConfig(oidc_discovery_url=HYDRA_OIDC_ENDPOINT),
            # automation_callback is purely for simulating the user interaction
            automation_callback=automation_callback
        )
    )

    # 5. Execute
    token = oauth_client.token()

    # 6. Verify
    assert isinstance(token, str)
    assert_is_jwt_with_signature_verification(token, get_jwks_from_oidc(HYDRA_OIDC_ENDPOINT))
    print("Hydra authorization code flow oidc completed successfully.")


def test_authorization_code_flow_oidc_no_secrets():
    """Tests the authorization code flow against the Hydra test environment."""
    check_hydra_running()

    # 1. Purge existing tokens
    purge_tokens(AUTHORIZATION_CODE_CLIENT["client_id"], AuthorizationCodeConfig)

    # 2. Initialize Helper
    hydra_automator = HydraAutoConsent(admin_url=HYDRA_ADMIN_URL)

    # 3. Define the automation behavior
    # We use a mutable container to capture the callback URL returned by Hydra
    flow_result: dict[str, str | None] = {"full_redirect_url": None}

    def automation_callback(url: str) -> str:
        # This function mimics the user opening the browser and logging in.
        # It returns the full redirect URL (e.g., localhost:5555/callback?code=...)
        # which our oauth_authorization_mode.py logic will then parse.
        result_url = hydra_automator.complete_auth_flow(url)
        flow_result["full_redirect_url"] = result_url
        return result_url

    # 4. Initialize Client
    oauth_client = OAuth2Client(
        config=AuthorizationCodeConfig(
            client_id=AUTHORIZATION_CODE_CLIENT_WITH_SCOPES["client_id"],
            scope="openid offline",
            redirect_uri=AUTHORIZATION_CODE_CLIENT_WITH_SCOPES["redirect_uris"][0],
            url_config=OidcConfig(oidc_discovery_url=HYDRA_OIDC_ENDPOINT),
            # automation_callback is purely for simulating the user interaction
            automation_callback=automation_callback
        )
    )

    # 5. Execute
    token = oauth_client.token()

    # 6. Verify
    assert isinstance(token, str)
    assert_is_jwt_with_signature_verification(token, get_jwks_from_oidc(HYDRA_OIDC_ENDPOINT))
    print("Hydra authorization code flow oidc no secrets completed successfully.")

def test_intentional_failure():
    """Simple test to verify CI failure reporting."""
    assert True is False, "PR TEST: This test is designed to fail."

if __name__ == "__main__":
    pytest.main([__file__])
