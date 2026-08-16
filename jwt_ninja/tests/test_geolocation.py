import io
import json

import pytest
from django.test import override_settings

from .. import settings as jwt_settings_module
from ..geolocation import ipapi_co_geolocator, resolve_location
from ..types import GeoLocation


def working_geolocator(ip_address: str) -> GeoLocation:
    return GeoLocation(city="Lisbon", country="Portugal", country_code="PT")


def exploding_geolocator(ip_address: str) -> GeoLocation:
    raise RuntimeError("provider outage")


def test_resolve_location_returns_none_without_provider():
    assert resolve_location("8.8.8.8") is None


@override_settings(JWT_GEOLOCATION_PROVIDER="jwt_ninja.tests.test_geolocation.working_geolocator")
def test_resolve_location_uses_configured_provider():
    location = resolve_location("8.8.8.8")

    assert location is not None
    assert location.city == "Lisbon"
    assert location.country_code == "PT"


@override_settings(JWT_GEOLOCATION_PROVIDER="jwt_ninja.tests.test_geolocation.working_geolocator")
@pytest.mark.parametrize(
    "ip_address",
    [
        None,
        "",
        "not-an-ip",
        "127.0.0.1",  # loopback
        "192.168.1.10",  # private
        "10.0.0.1",  # private
        "169.254.0.5",  # link-local
        "::1",  # IPv6 loopback
        "fe80::1",  # IPv6 link-local
    ],
)
def test_resolve_location_skips_unroutable_addresses(ip_address):
    assert resolve_location(ip_address) is None


def test_resolve_location_does_not_call_provider_for_private_ip(mocker):
    provider = mocker.Mock()
    mocker.patch.object(jwt_settings_module.jwt_settings, "_GEOLOCATION_PROVIDER", provider)

    assert resolve_location("192.168.1.10") is None
    provider.assert_not_called()


@override_settings(JWT_GEOLOCATION_PROVIDER="jwt_ninja.tests.test_geolocation.exploding_geolocator")
def test_resolve_location_swallows_provider_failures():
    assert resolve_location("8.8.8.8") is None


def _mock_urlopen(mocker, payload: dict):
    response = mocker.MagicMock()
    response.__enter__.return_value = io.BytesIO(json.dumps(payload).encode())
    return mocker.patch("jwt_ninja.geolocation.urllib.request.urlopen", return_value=response)


def test_ipapi_co_geolocator_parses_response(mocker):
    urlopen = _mock_urlopen(
        mocker,
        {
            "city": "Mountain View",
            "region": "California",
            "country_name": "United States",
            "country_code": "US",
            "latitude": 37.42,
            "longitude": -122.08,
        },
    )

    location = ipapi_co_geolocator("8.8.8.8")

    assert location == GeoLocation(
        city="Mountain View",
        region="California",
        country="United States",
        country_code="US",
        latitude=37.42,
        longitude=-122.08,
    )
    request = urlopen.call_args.args[0]
    assert request.full_url == "https://ipapi.co/8.8.8.8/json/"


def test_ipapi_co_geolocator_returns_none_on_error_payload(mocker):
    _mock_urlopen(mocker, {"error": True, "reason": "RateLimited"})

    assert ipapi_co_geolocator("8.8.8.8") is None
