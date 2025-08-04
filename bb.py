from deepteam.vulnerabilities import CustomVulnerability
from deepteam.attacks import Base64
from deepteam import red_team

api_security = CustomVulnerability(
    criteria="Security database",
    name="API Security",  # Name reflecting the security concern
    types=["endpoint_exposure", "auth_bypass"],  # Specific aspects to test
)


async def model_callback(input: str) -> str:
    return f"I'm sorry but I can't answer this: {input}"


red_team(
    model_callback=model_callback,
    vulnerabilities=[
        api_security,
    ],
    attacks=[],
    ignore_errors=True,
    run_async=True,
)
