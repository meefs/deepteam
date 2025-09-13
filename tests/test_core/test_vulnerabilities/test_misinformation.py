import pytest

from deepteam.vulnerabilities import Misinformation
from deepteam.vulnerabilities.misinformation import MisinformationType


class TestMisinformation:
    MISINFORMATION = "category"

    def test_misinformation_all_types(self):
        types = [
            "factual errors",
            "unsupported claims",
            "expertize misrepresentation",
        ]
        misinformation = Misinformation(
            misinformation_category=TestMisinformation.MISINFORMATION,
            types=types,
        )
        assert sorted(type.value for type in misinformation.types) == sorted(
            types
        )

    def test_misinformation_all_types_default(self):
        misinformation = Misinformation(
            misinformation_category=TestMisinformation.MISINFORMATION,
        )
        assert sorted(type.value for type in misinformation.types) == sorted(
            type.value for type in MisinformationType
        )

    def test_misinformation_factual_errors(self):
        types = ["factual errors"]
        misinformation = Misinformation(
            misinformation_category=TestMisinformation.MISINFORMATION,
            types=types,
        )
        assert sorted(type.value for type in misinformation.types) == sorted(
            types
        )

    def test_misinformation_unsupported_claims(self):
        types = ["unsupported claims"]
        misinformation = Misinformation(
            misinformation_category=TestMisinformation.MISINFORMATION,
            types=types,
        )
        assert sorted(type.value for type in misinformation.types) == sorted(
            types
        )

    def test_misinformation_expertize_misrepresentation(self):
        types = ["expertize misrepresentation"]
        misinformation = Misinformation(
            misinformation_category=TestMisinformation.MISINFORMATION,
            types=types,
        )
        assert sorted(type.value for type in misinformation.types) == sorted(
            types
        )

    def test_misinformation_all_types_invalid(self):
        types = [
            "factual errors",
            "unsupported claims",
            "expertize misrepresentation",
            "invalid",
        ]
        with pytest.raises(ValueError):
            Misinformation(
                misinformation_category=TestMisinformation.MISINFORMATION,
                types=types,
            )
