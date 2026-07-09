class IdentityAdapter:
    """Adapts user authentication window features to the IdentityDetector contract.

    LANL is auth-based. In a live environment, incoming authentication logs
    from Active Directory, LDAP, or VPN gateways would be windowed and
    aggregated before running inference.
    """

    def adapt(self, event: dict) -> dict:
        return {
            "entity_id": event.get("entity_id", "unknown-user"),
            "timestamp": event.get("timestamp", ""),
            "features": event["data"],
        }
