from ...active_operations import run_active_operation as run_legacy_operation
from ...infrastructure.workers.discovery_executor import (
    run_discovery_operation,
    supports as supports_discovery_operation,
)


def run_operation(operation: str, target: str, payload: dict, principal):
    if supports_discovery_operation(operation):
        return run_discovery_operation(operation,target,payload,principal)
    return run_legacy_operation(operation,target,payload,principal)
