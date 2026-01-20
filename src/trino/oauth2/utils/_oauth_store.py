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

"""
functions for store oauth_tokens in local cache
"""

import inspect
import time
from typing import Optional, Union, Type

import jwt
import keyring
from trino.oauth2 import configs
from trino.oauth2.models import ClientCredentialsConfig, DeviceCodeConfig, AuthorizationCodeConfig

# Service name for keyring
SERVICE_NAME = "trino-python-client"
ACCESS_TOKEN_SUFFIX = "access_token"
REFRESH_TOKEN_SUFFIX = "refresh_token"

def _validate_mode(mode_name: str) -> None:
    """Validates the mode name against a list of allowed modes."""
    allowed_modes = ["ClientCredentialsConfig", "DeviceCodeConfig", "AuthorizationCodeConfig"]
    if mode_name not in allowed_modes:
        raise ValueError(
            f"Invalid mode '{mode_name}'. Allowed modes are: {', '.join(allowed_modes)}"
        )

def _get_keyring_username(client_id: str, mode: str, token_type: str) -> str:
    """Create a unique username for the keyring entry."""
    _validate_mode(mode)
    return f"{client_id}:{mode}:{token_type}"


def _has_active_access_token(
    access_token: Optional[str],
    valid_min_duration_threshold: int,
) -> bool:
    """
    check if the store has valid access token
    """
    if not access_token:
        return False

    try:
        decoded_data = jwt.decode(jwt=access_token, options={"verify_signature": False})
        token_expires_at = decoded_data["exp"]
        seconds_until_expiration = token_expires_at - time.time()
        return seconds_until_expiration >= valid_min_duration_threshold
    except Exception:
        return False


def get_active_access_token(
    client_id: str,
    mode: str,
    valid_min_duration_threshold: int = configs.VALID_MIN_DURATION_THRESHOLD,
) -> Optional[str]:
    username = _get_keyring_username(client_id, mode, ACCESS_TOKEN_SUFFIX)
    try:
        access_token = keyring.get_password(SERVICE_NAME, username)
    except keyring.errors.NoKeyringError:
        print(
            "[ERROR] No recommended keyring backend available. Falling back to "
            "plaintext file backend. Your tokens will be stored UNENCRYPTED. "
            "For secure storage, install a system keyring backend."
        )
        try:
            from keyrings.alt.file import PlaintextKeyring
            keyring.set_keyring(PlaintextKeyring())
            access_token = keyring.get_password(SERVICE_NAME, username)
        except ImportError:
            print("[ERROR] keyrings.alt is not installed. Please install it with 'pip install keyrings.alt'.")
            return None
    return (
        access_token
        if _has_active_access_token(
            access_token=access_token,
            valid_min_duration_threshold=valid_min_duration_threshold,
        )
        else None
    )


def set_access_token(client_id: str, mode: str, access_token: str) -> None:
    username = _get_keyring_username(client_id, mode, ACCESS_TOKEN_SUFFIX)
    keyring.set_password(SERVICE_NAME, username, access_token)


def get_refresh_token(client_id: str, mode: str) -> Optional[str]:
    username = _get_keyring_username(client_id, mode, REFRESH_TOKEN_SUFFIX)
    return keyring.get_password(SERVICE_NAME, username)


def set_access_and_refresh_tokens(
    client_id: str, mode: str, access_token: str, refresh_token: str
) -> None:
    set_access_token(client_id, mode, access_token)
    refresh_username = _get_keyring_username(client_id, mode, REFRESH_TOKEN_SUFFIX)
    keyring.set_password(SERVICE_NAME, refresh_username, refresh_token)


"""Purges stored access and refresh tokens from the keyring.

This function can be called in several ways to specify which tokens to purge based on the `mode` parameter.

Args:
    client_id: The client ID for which to purge tokens.
    mode: Specifies which token(s) to purge. The allowed modes are
        `DeviceCodeConfig` and `ClientCredentialsConfig`. This can be one of the following:
        - None (default): Purges tokens for all supported modes.
        - A config class instance (e.g., `DeviceCodeConfig(...)`):
          Purges tokens for the mode of the given instance.
        - A config class type (e.g., `DeviceCodeConfig`):
          Purges tokens for the specified mode class.
        - A string with the mode name (e.g., `"DeviceCodeConfig"`):
          Purges tokens for the specified mode name.
"""
def purge_tokens(
    client_id: str,
    mode: Optional[Union[
            ClientCredentialsConfig,
            DeviceCodeConfig,
            AuthorizationCodeConfig,
            Type[ClientCredentialsConfig],
            Type[DeviceCodeConfig],
            Type[AuthorizationCodeConfig]
        ]] = None
) -> None:

    modes_to_purge = []
    if mode is not None:
        mode_name = ""
        if isinstance(mode, str):
            mode_name = mode
        elif inspect.isclass(mode):
            mode_name = mode.__name__
        else:
            mode_name = type(mode).__name__

        modes_to_purge = [mode_name]
    else:
        modes_to_purge = ["ClientCredentialsConfig", "DeviceCodeConfig"]

    for mode_name in modes_to_purge:
        access_username = _get_keyring_username(client_id, mode_name, ACCESS_TOKEN_SUFFIX)
        refresh_username = _get_keyring_username(client_id, mode_name, REFRESH_TOKEN_SUFFIX)
        try:
            keyring.delete_password(SERVICE_NAME, access_username)
        except keyring.errors.PasswordDeleteError:
            pass
        try:
            keyring.delete_password(SERVICE_NAME, refresh_username)
        except keyring.errors.PasswordDeleteError:
            pass