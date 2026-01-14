# pylint: disable=too-many-instance-attributes
from dataclasses import dataclass
from typing import Optional, Union, Callable


@dataclass
class OidcConfig:
    """
    Configuration for OpenID Connect (OIDC) discovery.

    This configuration method allows the client to automatically discover
    endpoints (like token, authorization, and device endpoints) by querying
    a standard metadata URL.
    """

    oidc_discovery_url: str
    """
    The URL of the OIDC discovery document (usually ends in 
    `/.well-known/openid-configuration`).

    Example: `https://auth.example.com/.well-known/openid-configuration`
    """


@dataclass
class ManualUrlsConfig:
    """
    Manual configuration for OAuth 2.0 endpoints.

    Use this configuration when OIDC discovery is not available or when
    specific endpoints need to be overridden.
    """

    token_endpoint: str
    """
    The URL of the token endpoint where access tokens are requested.
    Required for all OAuth flows.
    """

    device_authorization_endpoint: Optional[str] = None
    """
    The URL of the device authorization endpoint. 
    **Required only** for the Device Code flow.
    """

    authorization_endpoint: Optional[str] = None
    """
    The URL of the authorization endpoint where the user is directed to log in.
    **Required only** for the Authorization Code flow.
    """


@dataclass
class ClientCredentialsConfig:
    """
    Configuration for the OAuth 2.0 Client Credentials Grant flow.

    This flow is used for machine-to-machine (M2M) authentication where
    no user interaction is present. The application authenticates as itself.
    """

    client_id: str
    """
    The public identifier for the application (client).
    """

    client_secret: str
    """
    The secret credential for the application. Since Client Credentials flow 
    implies a confidential client, this is required.
    """

    url_config: Union[OidcConfig, ManualUrlsConfig]
    """
    Configuration for finding the necessary OAuth endpoints.
    """

    scope: Optional[str] = None
    """
    A space-delimited string defining the permissions the application is requesting.
    """

    audience: Optional[str] = None
    """
    A space-delimited string of audience identifiers (resource indicators)
    for which the token is intended. Used in OAuth 2.0 to specify target
    APIs or services that will accept the token.
    """


@dataclass
class DeviceCodeConfig:
    """
    Configuration for the OAuth 2.0 Device Code Grant flow.

    This flow is designed for internet-connected devices that either lack a
    browser or have limited input capability (e.g., smart TVs, CLI tools).
    """

    client_id: str
    """
    The public identifier for the application (client).
    """

    url_config: Union[OidcConfig, ManualUrlsConfig]
    """
    Configuration for finding the necessary OAuth endpoints.
    """

    client_secret: Optional[str] = None
    """
    The secret credential for the application.
    Optional because Device Code flow is often used by public clients 
    (which cannot safely store secrets).
    """

    scope: Optional[str] = None
    """
    A space-delimited string defining the permissions the application is requesting.
    """

    audience: Optional[str] = None
    """
    A space-delimited string of audience identifiers (resource indicators)
    for which the token is intended. Used in OAuth 2.0 to specify target
    APIs or services that will accept the token.
    """

    poll_for_token: bool = True
    """
    If True, the client will automatically poll the token endpoint 
    while waiting for the user to complete the login in a separate browser.

    If False, the client may wait for a user signal (like pressing Enter) 
    before attempting to fetch the token.
    """

    automation_callback: Optional[Callable[[str], None]] = None
    """
    A callback function used for automated testing.

    - **Input**: The `verification_uri_complete` (URL) that the user needs to visit.
    - **Output**: None.
    - **Behavior**: In Device Code flow, the automation is expected to visit the URL
      and approve the request. Unlike Auth Code flow, no return value (callback URL) 
      is needed because the device client polls the server directly for the token.
    """


@dataclass
class AuthorizationCodeConfig:
    """
    Configuration for the OAuth 2.0 Authorization Code Grant flow.

    This dataclass holds all necessary parameters to initiate and complete
    the standard authorization code flow, including client identifiers,
    endpoints, and security settings.
    """

    client_id: str
    """
    The public identifier for the application, obtained from the 
    OAuth provider (Authorization Server).
    """

    url_config: Union[OidcConfig, ManualUrlsConfig]
    """
    Configuration for OAuth endpoints.

    - Use `OidcConfig` to automatically discover endpoints via a .well-known URL.
    - Use `ManualUrlsConfig` to explicitly specify `authorization_endpoint` 
      and `token_endpoint`.
    """

    redirect_uri: str
    """
    The URI where the Authorization Server will redirect the user-agent 
    after granting access. This must exactly match one of the redirect URIs 
    registered with the OAuth provider.
    """

    client_secret: Optional[str] = None
    """
    The secret known only to the application and the authorization server.
    Required for confidential clients (web apps) but often omitted for 
    public clients (native/mobile apps) or when using PKCE without a secret.
    """

    scope: Optional[str] = None
    """
    A space-delimited string defining the permissions the application is 
    requesting. Examples: "openid profile email offline_access".
    """

    audience: Optional[str] = None
    """
    A space-delimited string of audience identifiers (resource indicators)
    for which the token is intended. Used in OAuth 2.0 to specify target
    APIs or services that will accept the token.
    """

    state: Optional[str] = None
    """
    An opaque value used to maintain state between the request and the callback.

    - **Security**: It is critical for preventing Cross-Site Request Forgery (CSRF).
    - If `None` (default), the library will automatically generate a secure 
      random string and verify it upon return.
    - If provided, the library will send this value and verify the same value 
      is returned in the redirect.
    """

    use_pkce: bool = True
    """
    Enables Proof Key for Code Exchange (PKCE).

    - **Default**: True.
    - PKCE is highly recommended for all clients (public and confidential) to 
      prevent authorization code injection attacks.
    """

    automation_callback: Optional[Callable[[str], str]] = None
    """
    A callback function used for automated testing or headless environments.

    - **Input**: The constructed authorization URL (str).
    - **Output**: The full redirect URL (str) containing the `code` and `state`.
    - **Behavior**: If provided, the library calls this function instead of 
      opening a browser. The function is expected to programmatically visit 
      the auth URL, handle login/consent, and return the final URL the 
      browser was redirected to.
    """
