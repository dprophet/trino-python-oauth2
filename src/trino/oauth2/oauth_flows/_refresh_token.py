from typing import Optional, Dict, Union
from requests_oauthlib import OAuth2Session

from trino.oauth2.models import DeviceCodeConfig, AuthorizationCodeConfig
from trino.oauth2.utils import _oauth_store
from trino.oauth2.utils._oauth_store import (
    get_refresh_token,
    set_access_and_refresh_tokens,
)
from trino.oauth2.utils.proxies import get_proxies


def refresh_token(
    config: Union[DeviceCodeConfig, AuthorizationCodeConfig],
    refresh_url: str,
    proxy_url: Optional[str] = None,
) -> str:
    client_id = config.client_id
    client_secret = config.client_secret
    refresh_token = get_refresh_token(client_id=client_id, mode=type(config).__name__)
    if not refresh_token:
        raise ValueError("Invalid empty refresh token")

    params: Dict[str, str] = {
        "client_id": client_id,
        "client_secret": client_secret,
    }

    oauth_session = OAuth2Session(client_id, token={"refresh_token": refresh_token})
    token_data = oauth_session.refresh_token(  # type: ignore
        refresh_url,
        proxies=get_proxies(proxy_url=proxy_url),
        **params,  # type: ignore
    )

    set_access_and_refresh_tokens(
        client_id,
        type(config).__name__,
        token_data["access_token"],
        token_data["refresh_token"]
    )
    access_token = _oauth_store.get_active_access_token(
        client_id=client_id, mode=type(config).__name__
    )
    if not access_token:
        raise RuntimeError("Fail to retrieve access token")
    return access_token
