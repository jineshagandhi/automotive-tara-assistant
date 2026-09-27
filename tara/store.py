"""SQLite persistence: projects, review decisions, audit log and baselines.

Every change an analyst makes (override, review decision, control, coverage
disposition) is written to the audit log with user and timestamp, as the
case study requires traceability and human approval of AI suggestions.
"""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from tara import DATA_DIR

DEFAULT_DB = DATA_DIR / "tara.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    architecture TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reviews (
    project_id TEXT NOT NULL,
    item_id TEXT NOT NULL,
    status TEXT NOT NULL,
    reviewer TEXT NOT NULL,
    comment TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project_id, item_id)
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT NOT NULL,
    at TEXT NOT NULL,
    user TEXT NOT NULL,
    action TEXT NOT NULL,
    item_id TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS baselines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    result TEXT NOT NULL
);
"""

REVIEW_STATES = ["Proposed", "Accepted", "Modified", "Rejected"]


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path=DEFAULT_DB):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript(SCHEMA)

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    # ------------------------------------------------------------ projects

    def save_project(self, project_id, name, architecture_yaml, state):
        with self._connect() as db:
            db.execute(
                "INSERT INTO projects (id, name, architecture, state, updated_at) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET name=excluded.name, architecture=excluded.architecture, "
                "state=excluded.state, updated_at=excluded.updated_at",
                (project_id, name, architecture_yaml, json.dumps(state), now()))

    def load_project(self, project_id):
        with self._connect() as db:
            row = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        if row is None:
            return None
        return {"id": row["id"], "name": row["name"], "architecture": row["architecture"],
                "state": json.loads(row["state"]), "updated_at": row["updated_at"]}

    def list_projects(self):
        with self._connect() as db:
            rows = db.execute("SELECT id, name, updated_at FROM projects ORDER BY updated_at DESC").fetchall()
        return [dict(row) for row in rows]

    def delete_project(self, project_id):
        with self._connect() as db:
            for table in ("projects", "reviews", "audit", "baselines"):
                column = "id" if table == "projects" else "project_id"
                db.execute("DELETE FROM %s WHERE %s = ?" % (table, column), (project_id,))

    # ------------------------------------------------------------ reviews

    def set_review(self, project_id, item_id, status, reviewer, comment=""):
        if status not in REVIEW_STATES:
            raise ValueError("Unknown review status %s" % status)
        with self._connect() as db:
            db.execute(
                "INSERT INTO reviews (project_id, item_id, status, reviewer, comment, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(project_id, item_id) DO UPDATE SET "
                "status=excluded.status, reviewer=excluded.reviewer, comment=excluded.comment, "
                "updated_at=excluded.updated_at",
                (project_id, item_id, status, reviewer, comment, now()))
        self.log(project_id, reviewer, "review", item_id, "%s%s" % (status, ": " + comment if comment else ""))

    def reviews(self, project_id):
        with self._connect() as db:
            rows = db.execute("SELECT * FROM reviews WHERE project_id = ?", (project_id,)).fetchall()
        return {row["item_id"]: dict(row) for row in rows}

    # ------------------------------------------------------------ audit

    def log(self, project_id, user, action, item_id="", detail=""):
        with self._connect() as db:
            db.execute("INSERT INTO audit (project_id, at, user, action, item_id, detail) VALUES (?, ?, ?, ?, ?, ?)",
                       (project_id, now(), user, action, item_id, detail))

    def audit(self, project_id, limit=500):
        with self._connect() as db:
            rows = db.execute("SELECT at, user, action, item_id, detail FROM audit WHERE project_id = ? "
                              "ORDER BY id DESC LIMIT ?", (project_id, limit)).fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------ baselines

    def save_baseline(self, project_id, name, result_json, user):
        with self._connect() as db:
            db.execute("INSERT INTO baselines (project_id, name, created_at, result) VALUES (?, ?, ?, ?)",
                       (project_id, name, now(), result_json))
        self.log(project_id, user, "baseline", name, "Baseline saved")

    def baselines(self, project_id):
        with self._connect() as db:
            rows = db.execute("SELECT id, name, created_at FROM baselines WHERE project_id = ? ORDER BY id DESC",
                              (project_id,)).fetchall()
        return [dict(row) for row in rows]

    def load_baseline(self, baseline_id):
        with self._connect() as db:
            row = db.execute("SELECT result FROM baselines WHERE id = ?", (baseline_id,)).fetchone()
        return row["result"] if row else None
