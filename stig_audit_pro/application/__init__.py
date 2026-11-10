"""Application services; optional Pro services load only when requested."""

from importlib import import_module


_EXPORTS = {
    "AuditService": "audit_service", "AuditServiceResult": "audit_service",
    "ReportService": "report_service", "RunService": "run_service",
    "DeviceScanOutcome": "scan_orchestrator", "ScanEvent": "scan_orchestrator",
    "ScanOrchestrator": "scan_orchestrator", "ScanSummary": "scan_orchestrator",
    "StigLifecycleService": "stig_lifecycle_service",
    "PreflightIssue": "preflight_service", "PreflightResult": "preflight_service",
    "PreflightService": "preflight_service", "PreflightSeverity": "preflight_service",
}
__all__ = list(_EXPORTS)


def __getattr__(name: str):
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(name)
    return getattr(import_module(f"{__name__}.{module}"), name)
