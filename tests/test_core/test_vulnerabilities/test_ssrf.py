import pytest

from deepteam.vulnerabilities import SSRF
from deepteam.vulnerabilities.ssrf import SSRFType


class TestSSRF:

    def test_ssrf_all_types(self):
        types = [
            "internal_service_access",
            "cloud_metadata_access",
            "port_scanning",
        ]
        ssrf = SSRF(types=types)
        assert sorted(type.value for type in ssrf.types) == sorted(types)

    def test_ssrf_all_types_default(self):
        ssrf = SSRF()
        assert sorted(type.value for type in ssrf.types) == sorted(
            type.value for type in SSRFType
        )

    def test_ssrf_internal_service_access(self):
        types = ["internal_service_access"]
        ssrf = SSRF(types=types)
        assert sorted(type.value for type in ssrf.types) == sorted(types)

    def test_ssrf_cloud_metadata_access(self):
        types = ["cloud_metadata_access"]
        ssrf = SSRF(types=types)
        assert sorted(type.value for type in ssrf.types) == sorted(types)

    def test_ssrf_port_scanning(self):
        types = ["port_scanning"]
        ssrf = SSRF(types=types)
        assert sorted(type.value for type in ssrf.types) == sorted(types)

    def test_ssrf_all_types_invalid(self):
        types = [
            "internal_service_access",
            "cloud_metadata_access",
            "port_scanning",
            "invalid",
        ]
        with pytest.raises(ValueError):
            SSRF(types=types)
