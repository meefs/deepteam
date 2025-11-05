from abc import ABC, abstractmethod


class BaseAttack(ABC):
    weight: int = 1
    multi_turn: bool = False
    name: str = None  # Subclasses should override this

    def get_name(self) -> str:
        return self.name if self.name else self.__class__.__name__
