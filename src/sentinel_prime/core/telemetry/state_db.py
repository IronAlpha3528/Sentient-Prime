import sqlite3
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[4]
DB_PATH = PROJECT_ROOT / "data" / "incidents.db"

class IncidentStateDB:
    """Lightweight SQLite database for tracking incident state (e.g., Pending Approval)."""
    
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    incident_data TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

    def upsert_incident(self, incident_id: str, status: str, incident_data: dict):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO incidents (incident_id, status, incident_data)
                VALUES (?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET
                    status = excluded.status,
                    incident_data = excluded.incident_data,
                    updated_at = CURRENT_TIMESTAMP
            """, (incident_id, status, json.dumps(incident_data)))

    def get_incident(self, incident_id: str) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT status, incident_data FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
            if row:
                return {
                    "status": row["status"],
                    "incident_data": json.loads(row["incident_data"])
                }
            return None

    def get_recent_memory(self, limit: int = 3) -> list:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT incident_id, status, incident_data FROM incidents ORDER BY updated_at DESC LIMIT ?", (limit,)).fetchall()
            memory = []
            for row in rows:
                data = json.loads(row["incident_data"])
                # Extract whatever AI reasoning is available from previous runs
                summary = "No summary available"
                if "story" in data and "summary" in data["story"]:
                    summary = data["story"]["summary"]
                elif "response_agent_plan" in data:
                    summary = "AI Action Taken"

                memory.append({
                    "incident_id": row["incident_id"],
                    "status": row["status"],
                    "entities": data.get("entities", {}),
                    "summary": summary
                })
            return memory
