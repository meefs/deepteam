from deepteam.attacks.base_attack import BaseAttack


class BaseSingleTurnAttack(BaseAttack):

    def enhance(self, attack: str, *args, **kwargs) -> str:
        pass

    async def a_enhance(self, attack: str, *args, **kwargs) -> str:
        return self.enhance(attack, *args, **kwargs)
