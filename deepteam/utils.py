import inspect
from typing import Callable


def validate_model_callback_signature(
    model_callback: Callable,
    async_mode: bool,
):
    if async_mode and not inspect.iscoroutinefunction(model_callback):
        raise ValueError(
            "`model_callback` must be async. `async_mode` has been set to True."
        )
    if not async_mode and inspect.iscoroutinefunction(model_callback):
        raise ValueError(
            "`model_callback` must not be async. `async_mode` has been set to False."
        )
