import pytest

from deepteam.vulnerabilities import PromptLeakage
from deepteam.vulnerabilities.prompt_leakage import PromptLeakageType


class TestPromptLeakage:

    def test_prompt_leakage_all_types(self):
        types = [
            "secrets and credentials",
            "instructions",
            "guard exposure",
            "permissions and roles",
        ]
        prompt_leakage = PromptLeakage(types=types)
        assert sorted(type.value for type in prompt_leakage.types) == sorted(
            types
        )

    def test_prompt_leakage_all_types_default(self):
        prompt_leakage = PromptLeakage()
        assert sorted(type.value for type in prompt_leakage.types) == sorted(
            type.value for type in PromptLeakageType
        )

    def test_prompt_leakage_secrets_and_credentials(self):
        types = ["secrets and credentials"]
        prompt_leakage = PromptLeakage(types=types)
        assert sorted(type.value for type in prompt_leakage.types) == sorted(
            types
        )

    def test_prompt_leakage_instructions(self):
        types = ["instructions"]
        prompt_leakage = PromptLeakage(types=types)
        assert sorted(type.value for type in prompt_leakage.types) == sorted(
            types
        )

    def test_prompt_leakage_guard_exposure(self):
        types = ["guard exposure"]
        prompt_leakage = PromptLeakage(types=types)
        assert sorted(type.value for type in prompt_leakage.types) == sorted(
            types
        )

    def test_prompt_leakage_permissions_and_roles(self):
        types = ["permissions and roles"]
        prompt_leakage = PromptLeakage(types=types)
        assert sorted(type.value for type in prompt_leakage.types) == sorted(
            types
        )

    def test_prompt_leakage_all_types_invalid(self):
        types = [
            "secrets and credentials",
            "instructions",
            "guard exposure",
            "permissions and roles",
            "invalid",
        ]
        with pytest.raises(ValueError):
            PromptLeakage(types=types)
