"""Public lazy imports for the XFerry package."""

from importlib import import_module
from typing import TYPE_CHECKING, Any

from .config import (
    HIDDEN_FILES,
    __version__,  # noqa: F401 - re-export
)

if TYPE_CHECKING:
    from .http import HTTPRequest, HTTPResponse
    from .security import (
        BasicAuthenticator,
        check_openssl_available,
        compute_hmac,
        generate_random_credentials,
        generate_self_signed_cert,
        verify_hmac,
        xor_decrypt,
        xor_decrypt_with_hmac,
        xor_encrypt,
        xor_encrypt_with_hmac,
    )
    from .server import XFerryServer
    from .utils import generate_password_captcha

__all__ = [
    # Core
    "HTTPRequest",
    "HTTPResponse",
    "XFerryServer",
    # Security
    "BasicAuthenticator",
    "generate_random_credentials",
    "xor_encrypt",
    "xor_decrypt",
    "compute_hmac",
    "verify_hmac",
    "xor_encrypt_with_hmac",
    "xor_decrypt_with_hmac",
    "generate_self_signed_cert",
    "check_openssl_available",
    # Utils
    "generate_password_captcha",
    # Constants
    "HIDDEN_FILES",
    "__version__",
]

_LAZY_EXPORTS = {
    "HTTPRequest": ("xferry.http", "HTTPRequest"),
    "HTTPResponse": ("xferry.http", "HTTPResponse"),
    "XFerryServer": ("xferry.server", "XFerryServer"),
    "BasicAuthenticator": ("xferry.security", "BasicAuthenticator"),
    "generate_random_credentials": ("xferry.security", "generate_random_credentials"),
    "xor_encrypt": ("xferry.security", "xor_encrypt"),
    "xor_decrypt": ("xferry.security", "xor_decrypt"),
    "compute_hmac": ("xferry.security", "compute_hmac"),
    "verify_hmac": ("xferry.security", "verify_hmac"),
    "xor_encrypt_with_hmac": ("xferry.security", "xor_encrypt_with_hmac"),
    "xor_decrypt_with_hmac": ("xferry.security", "xor_decrypt_with_hmac"),
    "generate_self_signed_cert": ("xferry.security", "generate_self_signed_cert"),
    "check_openssl_available": ("xferry.security", "check_openssl_available"),
    "generate_password_captcha": ("xferry.utils", "generate_password_captcha"),
}


def __getattr__(name: str) -> Any:
    if name not in _LAZY_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    module_name, attr_name = _LAZY_EXPORTS[name]
    value = getattr(import_module(module_name), attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
