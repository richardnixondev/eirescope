"""Custom exceptions for EireScope."""


class EireScopeError(Exception):
    """Base exception for EireScope."""
    pass


class ValidationError(EireScopeError):
    """Invalid input data."""
    pass


class ModuleError(EireScopeError):
    """Error in an OSINT module."""
    pass


class ModuleNotFoundError(EireScopeError):
    """Requested module not found."""
    pass


class RateLimitError(EireScopeError):
    """Rate limited by external service."""
    pass


class APIKeyRequiredError(EireScopeError):
    """Module requires an API key that is not configured."""
    pass
