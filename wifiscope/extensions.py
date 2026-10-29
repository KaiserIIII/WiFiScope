"""Explicit lazy dispatch for the focused typed report extensions.

Capture and survey add their own calls here when implemented. No dynamic imports
from a report/catalog, plugin registration, or separate identity keys.
"""


def validate_extensions(report) -> None:
    if 'catalog_audit' in report:
        from .catalog_audit_schema import validate_catalog_audit
        validate_catalog_audit(report['catalog_audit'])
    if 'vulnerability_audit' in report:
        from .vulnerability_schema import validate_vulnerability_audit
        validate_vulnerability_audit(report['vulnerability_audit'])
    if 'capture_session' in report:
        from .capture_schema import validate_capture_session
        validate_capture_session(report['capture_session'])
    if 'wifi_survey' in report:
        from .survey_schema import validate_survey
        validate_survey(report['wifi_survey'])


def project_extensions(report, identity) -> dict:
    result = {}
    if 'catalog_audit' in report:
        from .catalog_audit_schema import project_catalog_audit
        result['catalog_audit'] = project_catalog_audit(report['catalog_audit'], identity)
    if 'vulnerability_audit' in report:
        from .vulnerability_schema import project_vulnerability_audit
        result['vulnerability_audit'] = project_vulnerability_audit(report['vulnerability_audit'], identity)
    if 'capture_session' in report:
        from .capture_schema import project_capture_session
        result['capture_session'] = project_capture_session(report['capture_session'], identity)
    if 'wifi_survey' in report:
        from .survey_schema import project_survey
        result['wifi_survey'] = project_survey(report['wifi_survey'], identity)
    return result
