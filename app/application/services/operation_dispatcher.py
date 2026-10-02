"""Deprecated application-layer dispatcher module.

Operation execution is composed by the infrastructure worker dispatcher.
Application code depends only on the OperationExecutor port.
"""

from ..ports.operation_executor import OperationExecutor

__all__=["OperationExecutor"]
