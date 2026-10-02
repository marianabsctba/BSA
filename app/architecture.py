"""Architecture boundaries for the BSA modular core.

api -> application -> domain/repositories -> infrastructure

Legacy modules remain available during the strangler migration and must not be
used as a reason to add new business logic to app.main.
"""

LAYERS=("api","application","domain","repositories","infrastructure")

BOUNDED_CONTEXTS=(
    "identity",
    "exposure",
    "discovery",
    "risk",
    "ctem",
    "digital_risk",
    "integrations",
    "operations",
)
