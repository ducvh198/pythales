"""
PayShield Error Codes and Exception definitions.
"""

class ErrorCodes:
    SUCCESS = "00"
    LMK_ERROR = "01"
    INVALID_KEY_TYPE = "02"
    INVALID_KEY_LENGTH = "04"
    KCV_MISMATCH = "10"
    INVALID_DATA_LENGTH = "15"
    INVALID_KEY_SCHEME = "20"
    INVALID_PIN_BLOCK = "23"
    FUNCTION_NOT_SUPPORTED = "80"
    INTERNAL_HARDWARE_ERROR = "90"


class PayShieldException(Exception):
    """Exception raised for PayShield HSM errors."""
    def __init__(self, error_code: str = ErrorCodes.FUNCTION_NOT_SUPPORTED, message: str = "HSM Error"):
        super().__init__(f"[{error_code}] {message}")
        self.error_code = error_code
        self.message = message
