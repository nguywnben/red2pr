"""Instance onboarding, setup wizard, outbound consent ledger & lifecycle operations."""

from red2pr_control.operations.router import build_operations_router
from red2pr_control.operations.setup_wizard import (
    DbEndpointAllowlistProvider,
    SetupStepProbeCallable,
    SetupStepProbeResult,
    SetupStepRegistry,
    SetupWizardService,
    build_setup_router,
    get_setup_wizard_service,
)

__all__ = [
    "DbEndpointAllowlistProvider",
    "SetupStepProbeCallable",
    "SetupStepProbeResult",
    "SetupStepRegistry",
    "SetupWizardService",
    "build_operations_router",
    "build_setup_router",
    "get_setup_wizard_service",
]
