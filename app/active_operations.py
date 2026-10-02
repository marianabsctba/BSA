"""Compatibility facade for the modular active-operation dispatcher.

New code should import app.application.services.operation_dispatcher.run_operation.
This module remains temporarily to preserve older imports while the monolith is reduced.
"""

from .application.services.operation_dispatcher import run_operation


def run_active_operation(operation: str, target: str, payload: dict, principal):
    return run_operation(operation,target,payload,principal)
