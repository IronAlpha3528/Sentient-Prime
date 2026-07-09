class TelemetryRouter:
    """Routes normalized telemetry to the matching adapter + detector."""

    def __init__(self, routes: dict):
        self.routes = routes

    def route(self, event: dict) -> dict:
        telemetry_type = event.get("telemetry_type")
        route = self.routes.get(telemetry_type)
        if route is None:
            raise ValueError(
                f"Unknown or not-yet-enabled telemetry type: {telemetry_type}"
            )

        adapter, detector = route
        adapted = adapter.adapt(event)
        return detector.predict(adapted)
