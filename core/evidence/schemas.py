from enum import Enum

class DetectorType(str, Enum):
    NETWORK = "NETWORK"
    IDENTITY = "IDENTITY"
    ENDPOINT = "ENDPOINT"
    OT = "OT"
    CLOUD = "CLOUD"
    EMAIL = "EMAIL"
    DNS = "DNS"

    @classmethod
    def has_value(cls, value: str) -> bool:
        return value.upper() in cls._value2member_map_

class EntityType(str, Enum):
    HOST = "HOST"
    USER = "USER"
    PROCESS = "PROCESS"
    DEVICE = "DEVICE"
    PLC = "PLC"
    SENSOR = "SENSOR"
    ACTUATOR = "ACTUATOR"
    NETWORK_FLOW = "NETWORK_FLOW"
    DOMAIN = "DOMAIN"
    FILE = "FILE"
    REGISTRY = "REGISTRY"
    SERVICE = "SERVICE"

    @classmethod
    def has_value(cls, value: str) -> bool:
        return value.upper() in cls._value2member_map_
