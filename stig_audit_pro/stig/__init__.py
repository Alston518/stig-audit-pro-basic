"""STIG adapters; source download and comparison stay outside Basic startup."""

from importlib import import_module


_EXPORTS = {
    "CklAsset": "ckl_writer", "CklError": "ckl_writer",
    "write_completed_ckl": "ckl_writer",
    "read_cklb": "cklb_writer", "write_completed_cklb": "cklb_writer",
    "StigSourceManager": "source_manager",
    "StigDiff": "stig_diff", "StigDiffEngine": "stig_diff",
    "StigBenchmarkMetadata": "stig_metadata", "StigRuleMetadata": "stig_metadata",
    "StigRepository": "stig_repository", "parse_xccdf_file": "xccdf_importer",
}
__all__ = list(_EXPORTS)


def __getattr__(name: str):
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(name)
    return getattr(import_module(f"{__name__}.{module}"), name)
