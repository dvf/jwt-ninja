import ipaddress

from django.http import HttpRequest

from . import settings as jwt_settings_module


def _parsed_ip(value: str | None):
    if not value or len(value) > 45:
        return None
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def _is_trusted_proxy(address) -> bool:
    for network in jwt_settings_module.jwt_settings.trusted_proxy_networks:
        try:
            if address in network:
                return True
        except TypeError:
            continue
    return False


def get_client_ip(request: HttpRequest) -> str | None:
    """Resolve a client address only through an explicitly trusted proxy chain."""
    remote = _parsed_ip(request.META.get("REMOTE_ADDR"))
    if remote is None:
        return None

    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    config = jwt_settings_module.jwt_settings
    if not forwarded or not _is_trusted_proxy(remote):
        return str(remote)
    if len(forwarded) > config.MAX_FORWARDED_HEADER_LENGTH:
        return str(remote)

    raw_chain = forwarded.split(",")
    if not raw_chain or len(raw_chain) > config.MAX_FORWARDED_HOPS:
        return str(remote)
    chain = [_parsed_ip(item) for item in raw_chain]
    # Reject the whole header if any hop is malformed; partial interpretation
    # lets an attacker change which address is selected.
    if any(address is None for address in chain):
        return str(remote)

    for address in reversed(chain):
        if not _is_trusted_proxy(address):
            return str(address)
    return str(remote)


def get_user_agent(request: HttpRequest) -> str:
    return request.headers.get("User-Agent", "")[:512]


_BROWSERS = [
    ("Edg", "Edge"),
    ("OPR/", "Opera"),
    ("Opera", "Opera"),
    ("SamsungBrowser", "Samsung Internet"),
    ("Firefox/", "Firefox"),
    ("FxiOS/", "Firefox"),
    ("CriOS/", "Chrome"),
    ("Chrome/", "Chrome"),
    ("Safari/", "Safari"),
]

_PLATFORMS = [
    ("Windows", "Windows"),
    ("iPhone", "iOS"),
    ("iPad", "iPadOS"),
    ("Mac OS X", "macOS"),
    ("Macintosh", "macOS"),
    ("Android", "Android"),
    ("CrOS", "ChromeOS"),
    ("Linux", "Linux"),
]


def summarize_user_agent(user_agent: str | None) -> str | None:
    if not user_agent:
        return None
    browser = _first_match(user_agent, _BROWSERS)
    platform = _first_match(user_agent, _PLATFORMS)
    if browser and platform:
        return f"{browser} on {platform}"
    return browser or platform


def _first_match(user_agent: str, table: list[tuple[str, str]]) -> str | None:
    for needle, label in table:
        if needle in user_agent:
            return label
    return None
