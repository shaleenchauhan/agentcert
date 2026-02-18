"""Custom exceptions for the AgentCert library."""


class AgentCertError(Exception):
    """Base exception for all AgentCert errors."""


class KeyGenerationError(AgentCertError):
    """Raised when key generation fails."""


class KeyLoadError(AgentCertError):
    """Raised when loading keys from a file fails."""


class CertificateError(AgentCertError):
    """Raised when certificate creation or manipulation fails."""


class SignatureError(AgentCertError):
    """Raised when a cryptographic signature is invalid."""


class AnchorError(AgentCertError):
    """Raised when Bitcoin anchoring fails."""


class VerificationError(AgentCertError):
    """Raised when certificate verification fails."""


class ChainError(AgentCertError):
    """Raised when certificate chain validation fails."""


class SerializationError(AgentCertError):
    """Raised when certificate serialization or deserialization fails."""


class AuditError(AgentCertError):
    """Raised when audit trail operations fail."""


class BatchError(AgentCertError):
    """Raised when Merkle batch operations fail."""
