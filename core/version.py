"""Release identity for the OCTOPUS application.

Protocol, persistence, report, and benchmark schema versions deliberately live
with their owning subsystems. Only the installable application release uses
this value.
"""

APPLICATION_VERSION = "1.1.0"
__version__ = APPLICATION_VERSION

__all__ = ["APPLICATION_VERSION", "__version__"]
