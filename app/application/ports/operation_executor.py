from typing import Protocol, Any


class OperationExecutor(Protocol):
    def __call__(
        self,
        operation: str,
        target: str,
        payload: dict,
        principal: Any,
    ) -> dict:
        ...
