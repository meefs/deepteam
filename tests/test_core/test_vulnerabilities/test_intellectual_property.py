import pytest

from deepteam.vulnerabilities import IntellectualProperty
from deepteam.vulnerabilities.intellectual_property import (
    IntellectualPropertyType,
)


class TestIntellectualProperty:

    def test_intellectual_property_all_types(self):
        types = [
            "imitation",
            "copyright violations",
            "trademark infringement",
            "patent disclosure",
        ]
        intellectual_property = IntellectualProperty(types=types)
        assert sorted(
            type.value for type in intellectual_property.types
        ) == sorted(types)

    def test_intellectual_property_all_types_default(self):
        intellectual_property = IntellectualProperty()
        assert sorted(
            type.value for type in intellectual_property.types
        ) == sorted(type.value for type in IntellectualPropertyType)

    def test_intellectual_property_imitation(self):
        types = ["imitation"]
        intellectual_property = IntellectualProperty(types=types)
        assert sorted(
            type.value for type in intellectual_property.types
        ) == sorted(types)

    def test_intellectual_property_copyright_violations(self):
        types = ["copyright violations"]
        intellectual_property = IntellectualProperty(types=types)
        assert sorted(
            type.value for type in intellectual_property.types
        ) == sorted(types)

    def test_intellectual_property_trademark_infringement(self):
        types = ["trademark infringement"]
        intellectual_property = IntellectualProperty(types=types)
        assert sorted(
            type.value for type in intellectual_property.types
        ) == sorted(types)

    def test_intellectual_property_patent_disclosure(self):
        types = ["patent disclosure"]
        intellectual_property = IntellectualProperty(types=types)
        assert sorted(
            type.value for type in intellectual_property.types
        ) == sorted(types)

    def test_intellectual_property_all_types_invalid(self):
        types = [
            "imitation",
            "copyright violations",
            "trademark infringement",
            "patent disclosure",
            "invalid",
        ]
        with pytest.raises(ValueError):
            IntellectualProperty(types=types)
