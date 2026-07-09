import json 
from pathlib import Path 

class EvidenceStream:
    def __init__(self, path: str = "data/runtime/evidence/events.jsonl"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def publish(self, evidence: dict) -> None:
        with self.path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(evidence, default=str) + "\n")
