import pytest
from deepteam.frameworks import BeaverTails
from deepteam import red_team


class TestBeaverTails:

    def test_beavertails_init(self):
        """Test that BeaverTails framework can be instantiated."""
        framework = BeaverTails()
        assert framework is not None

    def test_beavertails_name(self):
        """Test that BeaverTails framework has correct name."""
        framework = BeaverTails()
        assert framework.name == "BeaverTails"

    def test_beavertails_description(self):
        """Test that BeaverTails framework has correct description."""
        framework = BeaverTails()
        assert (
            framework.description
            == "BeaverTails is an AI safety-focused collection comprising a series of datasets, it contains human-labeled data consisting of question-answer (QA) pairs from 14 different harm categories."
        )

    def test_beavertails_red_team(self):
        """Test that BeaverTails framework can be used with red_team function."""

        def mock_model_callback(prompt: str) -> str:
            return (
                "I'm a helpful AI assistant. I cannot help with that request."
            )

        risk_assessment = red_team(
            model_callback=mock_model_callback,
            framework=BeaverTails(num_attacks=5),
            async_mode=False,
            ignore_errors=True,
        )

        assert risk_assessment is not None

    @pytest.mark.asyncio
    async def test_beavertails_async_red_team(self):
        """Test that BeaverTails framework can be used with red_team function in async mode."""

        async def mock_async_model_callback(prompt: str) -> str:
            return (
                "I'm a helpful AI assistant. I cannot help with that request."
            )

        risk_assessment = red_team(
            model_callback=mock_async_model_callback,
            framework=BeaverTails(num_attacks=5),
            async_mode=True,
            ignore_errors=True,
        )

        assert risk_assessment is not None
