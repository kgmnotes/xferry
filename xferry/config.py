"""
Server configuration.
"""

# Project version (single source of truth)
__version__ = "0.1.0"


# Hidden/service-owned paths are inaccessible via external file methods.
HIDDEN_FILES: frozenset[str] = frozenset(
    {
        ".opsec_config.json",
        ".env",
        ".gitignore",
        ".git",
        "__pycache__",
    }
)

# HTTP status codes
HTTP_STATUS_MESSAGES: dict[int, str] = {
    101: "Switching Protocols",
    200: "OK",
    201: "Created",
    204: "No Content",
    304: "Not Modified",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    413: "Payload Too Large",
    429: "Too Many Requests",
    500: "Internal Server Error",
    501: "Not Implemented",
}
