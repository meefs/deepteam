import pytest

from deepteam.vulnerabilities import ShellInjection
from deepteam.vulnerabilities.shell_injection import ShellInjectionType


class TestShellInjection:
    PURPOSE="purpose"

    def test_shell_injection_all_types(self):
        types = [
            "command_injection",
            "system_command_execution",
            "shell_escape_sequences",
        ]
        shell_injection = ShellInjection(purpose=TestShellInjection.PURPOSE, types=types)
        assert sorted(type.value for type in shell_injection.types) == sorted(
            types
        )

    def test_shell_injection_all_types_default(self):
        shell_injection = ShellInjection(purpose=TestShellInjection.PURPOSE, )
        assert sorted(type.value for type in shell_injection.types) == sorted(
            type.value for type in ShellInjectionType
        )

    def test_shell_injection_command_injection(self):
        types = ["command_injection"]
        shell_injection = ShellInjection(purpose=TestShellInjection.PURPOSE, types=types)
        assert sorted(type.value for type in shell_injection.types) == sorted(
            types
        )

    def test_shell_injection_system_command_execution(self):
        types = ["system_command_execution"]
        shell_injection = ShellInjection(purpose=TestShellInjection.PURPOSE, types=types)
        assert sorted(type.value for type in shell_injection.types) == sorted(
            types
        )

    def test_shell_injection_shell_escape_sequences(self):
        types = ["shell_escape_sequences"]
        shell_injection = ShellInjection(purpose=TestShellInjection.PURPOSE, types=types)
        assert sorted(type.value for type in shell_injection.types) == sorted(
            types
        )

    def test_shell_injection_all_types_invalid(self):
        types = [
            "command_injection",
            "system_command_execution",
            "shell_escape_sequences",
            "invalid",
        ]
        with pytest.raises(ValueError):
            ShellInjection(purpose=TestShellInjection.PURPOSE, types=types)
