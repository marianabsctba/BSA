from ...active_operations import run_active_operation as run_legacy_operation
from ...infrastructure.workers.discovery_executor import (
    run_discovery_operation,
    supports as supports_discovery_operation,
)
from ...infrastructure.workers.discovery_intelligence_executor import (
    run_discovery_intelligence_operation,
    supports as supports_discovery_intelligence_operation,
)
from ...infrastructure.workers.assessment_executor import (
    run_assessment_operation,
    supports as supports_assessment_operation,
)
from ...infrastructure.workers.technology_executor import (
    run_technology_operation,
    supports as supports_technology_operation,
)
from ...infrastructure.workers.easm_executor import (
    run_easm_operation,
    supports as supports_easm_operation,
)


def run_operation(operation: str, target: str, payload: dict, principal):
    if supports_assessment_operation(operation):
        return run_assessment_operation(operation,target,payload,principal)
    if supports_discovery_operation(operation):
        return run_discovery_operation(operation,target,payload,principal)
    if supports_discovery_intelligence_operation(operation):
        return run_discovery_intelligence_operation(operation,target,payload,principal)
    if supports_technology_operation(operation):
        return run_technology_operation(operation,target,payload,principal)
    if supports_easm_operation(operation):
        return run_easm_operation(operation,target,payload,principal)
    return run_legacy_operation(operation,target,payload,principal)
