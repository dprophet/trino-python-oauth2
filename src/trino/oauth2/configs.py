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
