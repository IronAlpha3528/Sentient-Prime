from enum import Enum

class SeverityLevel(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def has_value(cls, value: str) -> bool:
        return value.upper() in cls._value2member_map_
