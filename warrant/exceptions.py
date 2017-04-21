class WarrantException(Exception):
    """Base class for all Warrant exceptions"""


class ForceChangePasswordException(WarrantException):
    """Raised when the user is forced to change their password"""
