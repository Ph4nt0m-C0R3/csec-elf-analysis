"""Domain exceptions that are safe to translate into user messages."""


class ValidationError(ValueError):
    """The uploaded input is missing, unsupported, or malformed."""


class AnalysisError(RuntimeError):
    """The file passed validation but could not be analyzed."""


class AnalysisTimeout(AnalysisError):
    """The configured analysis deadline was exceeded."""

