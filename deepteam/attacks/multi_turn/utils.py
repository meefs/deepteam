from typing import List
from deepeval.test_case import Turn


def update_turn_history(
    turn_history: List[Turn], user_input: str, assistant_output: str
):
    turn_history.append(
        Turn(
            role="user",
            content=user_input,
        )
    )
    turn_history.append(
        Turn(
            role="assistant",
            content=assistant_output,
        )
    )

    return turn_history
