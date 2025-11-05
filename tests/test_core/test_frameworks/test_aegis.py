import pytest
from deepteam.frameworks import Aegis
from deepteam import red_team


class TestAegis:

    def test_aegis_init(self):
        """Test that Aegis framework can be instantiated."""
        framework = Aegis()
        assert framework is not None

    def test_aegis_name(self):
        """Test that Aegis framework has correct name."""
        framework = Aegis()
        assert framework.name == "Aegis"

    def test_aegis_description(self):
        """Test that Aegis framework has correct description."""
        framework = Aegis()
        assert framework.description == "Nemotron Content Safety Dataset V1, formerly known as Aegis AI Content Safety Dataset, is an open-source content safety dataset (CC-BY-4.0), which adheres to Nvidia's content safety taxonomy, covering 13 critical risk categories"

    def test_aegis_red_team(self):
        """Test that Aegis framework can be used with red_team function."""

        def mock_model_callback(prompt: str) -> str:
            return (
                "I'm a helpful AI assistant. I cannot help with that request."
            )

        risk_assessment = red_team(
            model_callback=mock_model_callback,
            framework=Aegis(num_attacks=5),
            async_mode=False,
            ignore_errors=True,
        )

        assert risk_assessment is not None

    @pytest.mark.asyncio
    async def test_aegis_async_red_team(self):
        """Test that Aegis framework can be used with red_team function in async mode."""

        async def mock_async_model_callback(prompt: str) -> str:
            return (
                "I'm a helpful AI assistant. I cannot help with that request."
            )

        risk_assessment = red_team(
            model_callback=mock_async_model_callback,
            framework=Aegis(num_attacks=5),
            async_mode=True,
            ignore_errors=True,
        )

        assert risk_assessment is not None