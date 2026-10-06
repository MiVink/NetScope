"""NetScope — educational web inspector."""

try:
    from importlib.metadata import version as _pkg_version

    __version__ = _pkg_version("netscope")
except Exception:  # package not installed (e.g. running from source)
    __version__ = "1.0.0"

__all__ = ["__version__"]
