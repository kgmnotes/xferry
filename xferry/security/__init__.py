"""Security exports with lazy TLS helpers."""

from importlib import import_module
from typing import TYPE_CHECKING, Any

from .auth import (
    BasicAuthenticator,
    generate_random_credentials,
    hash_password,
    parse_basic_auth,
    verify_password,
)
from .crypto import (
    aes_decrypt,
    aes_encrypt,
    compute_hmac,
    decrypt,
    encrypt,
    verify_hmac,
    xor_bytes,
    xor_decrypt,
    xor_decrypt_file,
    xor_decrypt_with_hmac,
    xor_encrypt,
    xor_encrypt_file,
    xor_encrypt_with_hmac,
    xor_file,
)

if TYPE_CHECKING:
    from .tls import (
        check_openssl_available,
        generate_cert_in_memory,
        generate_self_signed_cert,
        get_cert_info,
    )

__all__ = [
    "BasicAuthenticator",
    "parse_basic_auth",
    "hash_password",
    "verify_password",
    "generate_random_credentials",
    "aes_encrypt",
    "aes_decrypt",
    "encrypt",
    "decrypt",
    "xor_bytes",
    "xor_file",
    "xor_encrypt",
    "xor_decrypt",
    "xor_encrypt_file",
    "xor_decrypt_file",
    "compute_hmac",
    "verify_hmac",
    "xor_encrypt_with_hmac",
    "xor_decrypt_with_hmac",
    "generate_self_signed_cert",
    "generate_cert_in_memory",
    "check_openssl_available",
    "get_cert_info",
]

_LAZY_EXPORTS = {
    "generate_self_signed_cert": ("xferry.security.tls", "generate_self_signed_cert"),
    "generate_cert_in_memory": ("xferry.security.tls", "generate_cert_in_memory"),
    "check_openssl_available": ("xferry.security.tls", "check_openssl_available"),
    "get_cert_info": ("xferry.security.tls", "get_cert_info"),
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
