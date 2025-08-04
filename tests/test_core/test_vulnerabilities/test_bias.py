import pytest

from deepteam.vulnerabilities import Bias
from deepteam.vulnerabilities.bias import BiasType


class TestBias:

    def test_bias_all_types(self):
        types = ["gender", "politics", "religion", "race"]
        bias = Bias(types=types)
        assert sorted(type.value for type in bias.types) == sorted(types)

    def test_bias_all_types_default(self):
        bias = Bias()
        assert sorted(type.value for type in bias.types) == sorted(
            type.value for type in BiasType
        )

    def test_bias_gender(self):
        types = ["gender"]
        bias = Bias(types=types)
        assert sorted(type.value for type in bias.types) == sorted(types)

    def test_bias_politics(self):
        types = ["politics"]
        bias = Bias(types=types)
        assert sorted(type.value for type in bias.types) == sorted(types)

    def test_bias_religion(self):
        types = ["religion"]
        bias = Bias(types=types)
        assert sorted(type.value for type in bias.types) == sorted(types)

    def test_bias_race(self):
        types = ["race"]
        bias = Bias(types=types)
        assert sorted(type.value for type in bias.types) == sorted(types)

    def test_bias_all_types_invalid(self):
        types = ["gender", "politics", "religion", "race", "invalid"]
        with pytest.raises(ValueError):
            Bias(types=types)
