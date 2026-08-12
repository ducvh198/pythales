"""
PayShield Error Codes and Exception definitions.
"""


class ErrorCodes:
    SUCCESS = "00"
    LMK_ERROR = "01"
    LMK_INCORRECT_KEY = "01"
    INVALID_KEY_TYPE = "02"
    INVALID_KEY_LENGTH = "03"
    INVALID_KEY_USAGE = "04"
    KEY_NOT_SUITABLE = "05"
    KCV_MISMATCH = "10"
    INVALID_KEY_CHECK_VALUE = "10"
    INVALID_KEY_PARITY = "11"
    INVALID_KEY_SCHEME = "12"
    INVALID_KEY_BLOCK = "13"
    INVALID_DATA_LENGTH = "15"
    INVALID_INPUT_DATA = "17"
    INVALID_PIN_BLOCK_FORMAT = "21"
    INVALID_PIN_BLOCK = "23"
    PIN_LENGTH_OUT_OF_RANGE = "26"
    INVALID_DECIMALISATION_TABLE = "27"
    INVALID_OFFSET = "28"
    PIN_VERIFICATION_FAILED = "29"
    KEY_PARITY_ERROR = "68"
    DES_KEY_PARITY_ERROR = "68"
    FUNCTION_NOT_SUPPORTED = "80"
    KEY_EXPIRATION_ERROR = "83"
    SECURITY_POLICY_VIOLATION = "A6"
    PCI_KEY_SEPARATION_VIOLATION = "A7"
    DEK_DOWNGRADE_PROHIBITED = "A8"
    INVALID_ALGORITHM = "BC"
    INTERNAL_HARDWARE_ERROR = "90"

    ALL_CODES = (
        '00', '01', '02', '03', '04', '05', '10', '11', '12', '13',
        '15', '17', '21', '23', '26', '27', '28', '29', '68', '80',
        '83', 'A6', 'A7', 'A8', 'BC'
    )

    MESSAGES = {
        "00": "No error / Success",
        "01": "LMK error / Incorrect LMK key",
        "02": "Invalid key type",
        "03": "Invalid key length",
        "04": "Invalid key usage",
        "05": "Key not suitable",
        "10": "Key check value mismatch",
        "11": "Invalid key parity",
        "12": "Invalid key scheme",
        "13": "Invalid key block",
        "15": "Invalid data length",
        "17": "Invalid input data",
        "21": "Invalid PIN block format",
        "23": "Invalid PIN block",
        "26": "PIN length out of range",
        "27": "Invalid decimalisation table",
        "28": "Invalid offset",
        "29": "PIN verification failed",
        "68": "DES key parity error",
        "80": "Function not supported",
        "83": "Key expiration error",
        "A6": "Security policy violation",
        "A7": "PCI HSM key separation violation",
        "A8": "DEK variant protection / downgrade prohibited",
        "BC": "Invalid algorithm",
        "90": "Internal hardware error",
    }

    @classmethod
    def get_message(cls, error_code: str) -> str:
        return cls.MESSAGES.get(error_code, f"Unknown PayShield Error ({error_code})")


class PayShieldException(Exception):
    """Exception raised for PayShield HSM errors."""
    def __init__(self, error_code: str = ErrorCodes.FUNCTION_NOT_SUPPORTED, message: str = None):
        if message is None:
            message = ErrorCodes.get_message(error_code)
        super().__init__(f"[{error_code}] {message}")
        self.error_code = error_code
        self.message = message

