"""Incrementally committed event journal shared by ingestion and execution."""

import json
import time

from .db import now


class Journal:
    def __init__(self, db, run_id, callback=None):
        self.db, self.run_id, self.callback = db, run_id, callback
        self.started = time.monotonic()

    def emit(self, event_type, details=None, *, source="orchestrator", level="info", step="execution", attempt=1):
        event = dict(timestamp=now(), elapsed_ms=round((time.monotonic() - self.started) * 1000),
                     step=step, attempt=attempt, source=source, level=level,
                     type=event_type, details=details or {})
        with self.db.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            seq = con.execute("SELECT COALESCE(MAX(seq),0)+1 FROM events WHERE run_id=?", (self.run_id,)).fetchone()[0]
            con.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (self.run_id, seq, event["timestamp"], event["elapsed_ms"], step, attempt,
                         source, level, event_type, json.dumps(event["details"])))
        event.update(run_id=self.run_id, seq=seq)
        if self.callback:
            self.callback(event)
        return event
