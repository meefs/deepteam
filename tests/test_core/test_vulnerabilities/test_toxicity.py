import pytest

from deepteam.vulnerabilities import Toxicity
from deepteam.vulnerabilities.toxicity import ToxicityType


class TestToxicity:

    def test_toxicity_all_types(self):
        types = ["profanity", "insults", "threats", "mockery"]
        toxicity = Toxicity(types=types)
        assert sorted(type.value for type in toxicity.types) == sorted(types)

    def test_toxicity_all_types_default(self):
        toxicity = Toxicity()
        assert sorted(type.value for type in toxicity.types) == sorted(
            type.value for type in ToxicityType
        )

    def test_toxicity_profanity(self):
        types = ["profanity"]
        toxicity = Toxicity(types=types)
        assert sorted(type.value for type in toxicity.types) == sorted(types)

    def test_toxicity_insults(self):
        types = ["insults"]
        toxicity = Toxicity(types=types)
        assert sorted(type.value for type in toxicity.types) == sorted(types)

    def test_toxicity_threats(self):
        types = ["threats"]
        toxicity = Toxicity(types=types)
        assert sorted(type.value for type in toxicity.types) == sorted(types)

    def test_toxicity_mockery(self):
        types = ["mockery"]
        toxicity = Toxicity(types=types)
        assert sorted(type.value for type in toxicity.types) == sorted(types)

    def test_toxicity_all_types_invalid(self):
        types = ["profanity", "insults", "threats", "mockery", "invalid"]
        with pytest.raises(ValueError):
            Toxicity(types=types)
