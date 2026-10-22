"""Exception types. Anything derived from SbxError is shown to the model as-is; keep messages safe."""
from .guest.fscore import FsError  # noqa: F401  (re-exported: one class for host and guest code)


class ConfigError(Exception):
    """Invalid or unusable configuration. Fatal at startup."""


class SbxError(Exception):
    """A user-facing error: the message is returned to the model as-is."""


class BackendError(SbxError):
    """A container/VM runtime refused or failed an operation."""


class ShellError(SbxError):
    """A user-facing shell error."""
