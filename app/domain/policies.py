"""Domain-facing policy types.

This module is the stable domain import surface while persistence and legacy
implementations are migrated behind application/repository boundaries.
"""

from ..tenant_risk_policy import TenantRiskPolicy
from ..tenant_sla_policy import TenantSLAPolicy

__all__=["TenantRiskPolicy","TenantSLAPolicy"]
