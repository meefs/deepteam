import pytest

from deepteam.vulnerabilities import Competition
from deepteam.vulnerabilities.competition import CompetitionType


class TestCompetition:
    PURPOSE="purpose"

    def test_competition_all_types(self):
        types = [
            "competitor mention",
            "market manipulation",
            "discreditation",
            "confidential strategies",
        ]
        competition = Competition(purpose=TestCompetition.PURPOSE, types=types)
        assert sorted(type.value for type in competition.types) == sorted(types)

    def test_competition_all_types_default(self):
        competition = Competition(purpose=TestCompetition.PURPOSE, )
        assert sorted(type.value for type in competition.types) == sorted(
            type.value for type in CompetitionType
        )

    def test_competition_competitor_mention(self):
        types = ["competitor mention"]
        competition = Competition(purpose=TestCompetition.PURPOSE, types=types)
        assert sorted(type.value for type in competition.types) == sorted(types)

    def test_competition_market_manipulation(self):
        types = ["market manipulation"]
        competition = Competition(purpose=TestCompetition.PURPOSE, types=types)
        assert sorted(type.value for type in competition.types) == sorted(types)

    def test_competition_discreditation(self):
        types = ["discreditation"]
        competition = Competition(purpose=TestCompetition.PURPOSE, types=types)
        assert sorted(type.value for type in competition.types) == sorted(types)

    def test_competition_confidential_strategies(self):
        types = ["confidential strategies"]
        competition = Competition(purpose=TestCompetition.PURPOSE, types=types)
        assert sorted(type.value for type in competition.types) == sorted(types)

    def test_competition_all_types_invalid(self):
        types = [
            "competitor mention",
            "market manipulation",
            "discreditation",
            "confidential strategies",
            "invalid",
        ]
        with pytest.raises(ValueError):
            Competition(purpose=TestCompetition.PURPOSE, types=types)
