import ipaddress
import json
import logging
import urllib.error
import urllib.request

from . import settings as jwt_settings_module
from .types import GeoLocation

logger = logging.getLogger(__name__)


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "Geolocation redirects are disabled", headers, fp)


def resolve_location(ip_address: str | None) -> GeoLocation | None:
    provider = jwt_settings_module.jwt_settings.geolocation_provider
    if provider is None or not ip_address:
        return None
    try:
        if not ipaddress.ip_address(ip_address).is_global:
            return None
        value = provider(ip_address)
        return GeoLocation.model_validate(value) if value is not None else None
    except Exception as exc:
        # Do not include exception text or traceback: urllib exceptions may
        # contain the request URL and therefore the client's address.
        logger.warning("Geolocation provider failed (%s)", type(exc).__name__)
        return None


def ipapi_co_geolocator(ip_address: str) -> GeoLocation | None:
    parsed_ip = ipaddress.ip_address(ip_address)
    if not parsed_ip.is_global:
        raise ValueError("Geolocation requires a global IP address")
    config = jwt_settings_module.jwt_settings
    http_request = urllib.request.Request(
        f"https://ipapi.co/{parsed_ip.compressed}/json/",
        headers={"User-Agent": "jwtninja"},
    )
    opener = urllib.request.build_opener(_RejectRedirects())
    with opener.open(http_request, timeout=config.GEOLOCATION_TIMEOUT_SECONDS) as response:
        declared_length = response.headers.get("Content-Length") if hasattr(response, "headers") else None
        if declared_length is not None and int(declared_length) > config.GEOLOCATION_MAX_RESPONSE_BYTES:
            raise ValueError("Geolocation response is too large")
        raw = response.read(config.GEOLOCATION_MAX_RESPONSE_BYTES + 1)
    if len(raw) > config.GEOLOCATION_MAX_RESPONSE_BYTES:
        raise ValueError("Geolocation response is too large")
    data = json.loads(raw)
    if not isinstance(data, dict) or data.get("error"):
        return None
    return GeoLocation(
        city=data.get("city"),
        region=data.get("region"),
        country=data.get("country_name"),
        country_code=data.get("country_code"),
        latitude=data.get("latitude"),
        longitude=data.get("longitude"),
    )
