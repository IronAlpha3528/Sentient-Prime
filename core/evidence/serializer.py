import json
from typing import Any, Dict, Union
from core.evidence.base_evidence import BaseEvidence
from core.evidence.normalizer import normalize_evidence_object

try:
    import msgpack
    HAS_MSGPACK = True
except ImportError:
    HAS_MSGPACK = False

class EvidenceSerializer:
    """Handles serialization and deserialization of BaseEvidence objects to and from

    dictionaries, JSON strings, raw bytes, and optionally MessagePack formats.
    """

    @staticmethod
    def serialize(evidence: BaseEvidence, format: str = "json") -> Union[str, Dict[str, Any], bytes]:
        """Serializes a BaseEvidence object into the specified format: 'json', 'dict', 'bytes', 'msgpack'."""
        d = evidence.to_dict()
        
        # Ensure enums are fully serialized as strings
        d['detector'] = str(d['detector'])
        d['entity_type'] = str(d['entity_type'])
        d['severity'] = str(d['severity'])

        format_lower = format.lower()
        if format_lower == "dict":
            return d
        elif format_lower == "json":
            return json.dumps(d, default=str)
        elif format_lower == "bytes":
            return json.dumps(d, default=str).encode("utf-8")
        elif format_lower == "msgpack":
            if not HAS_MSGPACK:
                raise ImportError("msgpack module is not installed. Install msgpack to enable this format.")
            return msgpack.packb(d, use_bin_type=True)
        else:
            raise ValueError(f"Unsupported serialization format: {format}")

    @staticmethod
    def deserialize(data: Union[str, Dict[str, Any], bytes], format: str = "json") -> BaseEvidence:
        """Deserializes input data from standard formats into a typed, normalized BaseEvidence instance."""
        format_lower = format.lower()
        if format_lower == "dict" and isinstance(data, dict):
            raw_dict = data
        elif format_lower == "json" and isinstance(data, (str, bytes)):
            raw_str = data.decode("utf-8") if isinstance(data, bytes) else data
            raw_dict = json.loads(raw_str)
        elif format_lower == "bytes" and isinstance(data, bytes):
            raw_dict = json.loads(data.decode("utf-8"))
        elif format_lower == "msgpack" and isinstance(data, bytes):
            if not HAS_MSGPACK:
                raise ImportError("msgpack module is not installed. Install msgpack to enable this format.")
            raw_dict = msgpack.unpackb(data, raw=False)
        else:
            # Fallback format detection
            if isinstance(data, dict):
                raw_dict = data
            elif isinstance(data, bytes):
                try:
                    if HAS_MSGPACK:
                        raw_dict = msgpack.unpackb(data, raw=False)
                    else:
                        raw_dict = json.loads(data.decode("utf-8"))
                except Exception:
                    raw_dict = json.loads(data.decode("utf-8"))
            elif isinstance(data, str):
                raw_dict = json.loads(data)
            else:
                raise TypeError(f"Cannot deserialize input data of type {type(data)}")

        return normalize_evidence_object(raw_dict)

    @staticmethod
    def save(evidence: BaseEvidence, file_path: str, format: str = "json") -> None:
        """Saves serialized evidence to a file."""
        serialized = EvidenceSerializer.serialize(evidence, format=format)
        mode = "wb" if isinstance(serialized, bytes) else "w"
        encoding = None if "b" in mode else "utf-8"
        with open(file_path, mode, encoding=encoding) as f:
            f.write(serialized)

    @staticmethod
    def load(file_path: str, format: str = "json") -> BaseEvidence:
        """Loads and deserializes evidence from a file."""
        mode = "rb" if format.lower() in ["bytes", "msgpack"] else "r"
        encoding = None if "b" in mode else "utf-8"
        with open(file_path, mode, encoding=encoding) as f:
            content = f.read()
        return EvidenceSerializer.deserialize(content, format=format)
