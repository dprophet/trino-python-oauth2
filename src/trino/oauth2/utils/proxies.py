from typing import Optional


def get_proxies(proxy_url: Optional[str]) -> Optional[dict[str, str]]:
    if not proxy_url:
        return None

    return {"http": proxy_url, "https": proxy_url}
