class NetworkFlowAdapter:
    """Adapts already-computed flow features to the NetworkDetector contract.

    CSE-CIC-IDS2018 is flow-based. A single raw packet, Sysmon event, or Wazuh
    alert is NOT equivalent to a CICFlowMeter feature vector. In the live
    pipeline, Zeek/Suricata/NetFlow/IPFIX or a custom flow accumulator must
    calculate the same saved feature contract first.
    """

    def adapt(self, event: dict) -> dict:
        return {
            "entity_id": event.get("entity_id", "unknown-host"),
            "timestamp": event.get("timestamp", ""),
            "features": event["data"],
        }
