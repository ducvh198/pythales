"""
PayShield Error Codes and Exception definitions.
"""


class ErrorCodes:
    SUCCESS = "00"
    VERIFICATION_FAILURE = "01"
    INVALID_KEY_LENGTH = "02"
    INVALID_KEY_TYPE = "04"
    INVALID_KEY_LENGTH_FLAG = "05"
    SOURCE_KEY_PARITY_ERROR = "10"
    DESTINATION_KEY_PARITY_ERROR = "11"
    INVALID_INPUT_DATA = "15"
    NOT_AUTHORIZED = "17"
    INVALID_PIN_BLOCK_FORMAT = "21"
    INVALID_PIN_BLOCK = "23"
    PIN_LENGTH_OUT_OF_RANGE = "26"
    INVALID_DECIMALISATION_TABLE = "27"
    INVALID_OFFSET = "28"
    PIN_VERIFICATION_FAILED = "29"
    INTERNAL_HARDWARE_ERROR = "41"
    COMMAND_NOT_LICENSED = "67"
    COMMAND_DISABLED = "68"
    DATA_LENGTH_ERROR = "80"
    KEY_EXPIRATION_ERROR = "83"
    REQUEST_DATA_PARITY_ERROR = "90"
    INVALID_KEY_USAGE = "A6"
    INVALID_ALGORITHM = "A7"
    INVALID_MODE_OF_USE = "A8"
    REPEATED_OPTIONAL_BLOCK = "BC"
    INVALID_MODE = "02"
    INVALID_INPUT_FORMAT = "03"
    INVALID_OUTPUT_FORMAT = "04"
    INVALID_COMMAND_KEY_TYPE = "05"
    INVALID_MESSAGE_LENGTH = "06"
    FPE_CHARACTER_ERROR = "09"
    MODE_REQUIRES_AES_KB_LMK = "D1"
    MODE_REQUIRES_AES_KEY = "D2"

    # Compatibility aliases retained for callers of older pythales releases.
    # Their values now follow the Core Host Commands Guide definitions.
    LMK_ERROR = VERIFICATION_FAILURE
    LMK_INCORRECT_KEY = VERIFICATION_FAILURE
    KCV_MISMATCH = SOURCE_KEY_PARITY_ERROR
    INVALID_KEY_CHECK_VALUE = SOURCE_KEY_PARITY_ERROR
    INVALID_KEY_PARITY = DESTINATION_KEY_PARITY_ERROR
    INVALID_KEY_SCHEME = "26"
    INVALID_KEY_BLOCK = KEY_EXPIRATION_ERROR
    # Historical pythales name retained as an alias for the value it exposed.
    # New code should use INVALID_INPUT_DATA (15) or DATA_LENGTH_ERROR (80).
    INVALID_DATA_LENGTH = INVALID_INPUT_DATA
    FUNCTION_NOT_SUPPORTED = INVALID_INPUT_DATA
    KEY_PARITY_ERROR = REQUEST_DATA_PARITY_ERROR
    DES_KEY_PARITY_ERROR = REQUEST_DATA_PARITY_ERROR
    SECURITY_POLICY_VIOLATION = NOT_AUTHORIZED
    PCI_KEY_SEPARATION_VIOLATION = INVALID_ALGORITHM
    DEK_DOWNGRADE_PROHIBITED = INVALID_MODE_OF_USE
    INVALID_RANDOM_VALUE_LENGTH = VERIFICATION_FAILURE

    ALL_CODES = (
        '00', '01', '02', '03', '04', '05', '10', '11', '12', '13',
        '15', '17', '21', '23', '26', '27', '28', '29', '41', '67',
        '68', '80', '83', '90', 'A6', 'A7', 'A8', 'BC', 'D1', 'D2'
    )

    MESSAGES = {
        "00": "No error / Success",
        "01": "Verification failure or imported-key parity warning",
        "02": "Key inappropriate length for algorithm",
        "03": "Command-specific key error",
        "04": "Invalid key type code",
        "05": "Invalid key length flag",
        "10": "Source key parity error",
        "11": "Destination key parity error or key all zeros",
        "12": "Contents of user storage not available",
        "13": "Invalid LMK identifier",
        "15": "Invalid input data",
        "17": "HSM not authorized or operation prohibited by security settings",
        "21": "Invalid PIN block format",
        "23": "Invalid PIN block",
        "26": "PIN length out of range",
        "27": "Invalid decimalisation table",
        "28": "Invalid offset",
        "29": "PIN verification failed",
        "41": "Internal hardware/software error",
        "67": "Command not licensed",
        "68": "Command disabled",
        "80": "Data length error",
        "83": "Key block format error",
        "90": "Data parity error in request message",
        "A6": "Invalid key usage",
        "A7": "Invalid algorithm",
        "A8": "Invalid mode of use",
        "BC": "Repeated optional block",
        "D1": "Mode requires AES Key Block LMK",
        "D2": "Mode requires an AES key",
    }

    @classmethod
    def get_message(cls, error_code: str) -> str:
        return cls.MESSAGES.get(error_code, f"Unknown PayShield Error ({error_code})")


class PayShieldException(Exception):
    """Exception raised for PayShield HSM errors."""
    def __init__(self, error_code: str = ErrorCodes.INTERNAL_HARDWARE_ERROR, message: str = None):
        if message is None:
            message = ErrorCodes.get_message(error_code)
        super().__init__(f"[{error_code}] {message}")
        self.error_code = error_code
        self.message = message
