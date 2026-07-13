from enum import Enum

class NodeType(str, Enum):
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

class EdgeType(str, Enum):
    AUTHENTICATES_TO = "AUTHENTICATES_TO"
    RUNS_PROCESS = "RUNS_PROCESS"
    CONNECTS_TO = "CONNECTS_TO"
    SPAWNS = "SPAWNS"
    READS = "READS"
    WRITES = "WRITES"
    MODIFIES = "MODIFIES"
    CONTROLS = "CONTROLS"
    MEASURES = "MEASURES"
    ACCESSES = "ACCESSES"
    QUERIES = "QUERIES"
    USES = "USES"
    GENERATES = "GENERATES"
    OBSERVED_IN = "OBSERVED_IN"
    DETECTED_BY = "DETECTED_BY"

    @classmethod
    def has_value(cls, value: str) -> bool:
        return value.upper() in cls._value2member_map_
