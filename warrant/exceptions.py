class WarrantException(Exception):
    """Base class for all Warrant exceptions"""


class InvalidStateException(WarrantException):
    """Called when Warrant is in the wrong state for the current authentication operation"""


class ForceChangePasswordException(WarrantException):
    """Raised when the user is forced to change their password"""


class SecondFactorRequiredException(WarrantException):
    """Raised when the user is needs to provide a 2FA code"""


class TokenVerificationException(WarrantException):
    """Raised when token verification fails."""
