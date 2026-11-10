"""Report writers; Pro formats load only when requested."""

from importlib import import_module


_EXPORTS = {
    "write_excel_report": "excel_writer",
    "build_json_report": "json_writer",
    "write_json_report": "json_writer",
}
__all__ = list(_EXPORTS)


def __getattr__(name: str):
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(name)
    return getattr(import_module(f"{__name__}.{module}"), name)
