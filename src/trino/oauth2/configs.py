from enum import Enum

class OAuthFlow(Enum):
    CLIENT_CREDENTIALS = 1
    DEVICE_CODE = 2
    AUTH_CODE_PKCE = 3


# Map between Oauth flow enum and grant type string
OAUTHFLOW_GRANT_TYPES = {
    OAuthFlow.CLIENT_CREDENTIALS: "client_credentials",
    OAuthFlow.DEVICE_CODE: "urn:ietf:params:oauth:grant-type:device_code",
    OAuthFlow.AUTH_CODE_PKCE: "authorization_code"
}


# the access token mininum expiration duration (seconds)
VALID_MIN_DURATION_THRESHOLD = 30
# Request timeout limit (seconds)
REQUEST_TIMEOUT = 60

# LOCALHOST_REDIRECT_URI must not be changed as credential configs in
LOCALHOST_REDIRECT_URI = "http://localhost:61234/auth/token.callback"
