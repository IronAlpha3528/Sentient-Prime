class IdentityAdapter:
    """Adapts user authentication window features to the IdentityDetector contract.

    LANL is auth-based. In a live environment, incoming raw authentication events
    must pass through a stateful feature aggregator (maintaining user baselines,
    historical statistics, and seen destinations) to construct the following 12 features:
      - auth_count
      - unique_computers
      - fanout_rate
      - mean_auth_gap
      - min_auth_gap
      - max_auth_gap
      - new_computer_count
      - new_computer_ratio
      - auth_count_zscore
      - unique_computers_zscore
      - hour_of_day
      - off_hours_flag
    """

    def adapt(self, event: dict) -> dict:
        return {
            "entity_id": event.get("entity_id", "unknown-user"),
            "timestamp": event.get("timestamp", ""),
            "features": event["data"],
        }
