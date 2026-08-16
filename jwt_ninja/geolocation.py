import ipaddress
import json
import logging
import urllib.request

from . import settings as jwt_settings_module
from .types import GeoLocation

logger = logging.getLogger(__name__)

_HTTP_TIMEOUT_SECONDS = 5


def resolve_location(ip_address: str | None) -> GeoLocation | None:
    """
    Geolocate `ip_address` with the configured JWT_GEOLOCATION_PROVIDER.

    Returns None when no provider is configured, when the address is missing
    or not globally routable (private ranges, loopback, link-local — nothing
    a provider could place on a map), or when the provider fails. Provider
    failures are logged and swallowed: geolocation decorates the session list
    and must never fail the login it runs inside.
    """
    provider = jwt_settings_module.jwt_settings.geolocation_provider
    if provider is None or not ip_address:
        return None

    try:
        if not ipaddress.ip_address(ip_address).is_global:
            return None
    except ValueError:
        return None

    try:
        return provider(ip_address)
    except Exception:
        logger.warning("Geolocation provider failed for %s", ip_address, exc_info=True)
        return None


def ipapi_co_geolocator(ip_address: str) -> GeoLocation | None:
    """
    Free provider backed by https://ipapi.co — HTTPS, no API key, roughly
    1,000 lookups/day on the free tier.

    One blocking HTTP round-trip per call, so a login waits on it for up to
    _HTTP_TIMEOUT_SECONDS when the service is slow. Suitable for light
    traffic; beyond that, point JWT_GEOLOCATION_PROVIDER at an offline
    database such as MaxMind GeoLite2.
    """
    http_request = urllib.request.Request(
        f"https://ipapi.co/{ip_address}/json/",
        # ipapi.co rejects urllib's default User-Agent.
        headers={"User-Agent": "jwtninja"},
    )
    with urllib.request.urlopen(http_request, timeout=_HTTP_TIMEOUT_SECONDS) as response:
        data = json.load(response)

    # Over-quota and reserved-address responses come back as 200s with an
    # `error` flag rather than an HTTP error.
    if data.get("error"):
        return None

    return GeoLocation(
        city=data.get("city"),
        region=data.get("region"),
        country=data.get("country_name"),
        country_code=data.get("country_code"),
        latitude=data.get("latitude"),
        longitude=data.get("longitude"),
    )
