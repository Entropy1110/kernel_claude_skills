"""
State Management for Mali Static AI Skills

Provides session management, state serialization, and checkpoint utilities
for skill-based analysis workflows.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, TypedDict

from langgraph.checkpoint.sqlite import SqliteSaver


# Default checkpoint path
DEFAULT_CHECKPOINT_PATH = ".claude/state/mali-state/checkpoints.db"


class SessionInfo(TypedDict):
    """Metadata about an analysis session."""
    session_id: str
    created_at: str
    updated_at: str
    repo: str
    scope: str
    framework: str
    status: str  # "running", "completed", "failed", "paused"
    completed_stages: list[str]
    current_stage: str | None


@dataclass
class SkillState:
    """
    Extended state for skill-based execution.
    Wraps the core ScanState with additional skill-tracking fields.
    """
    # Core analysis state (mirrors ScanState from mali_static_ai.py)
    repo: str = ""
    scope: str = ""
    framework: str = "drm"
    candidates: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    tags: list[dict] = field(default_factory=list)
    tags_by_file: dict[str, list] = field(default_factory=dict)
    iteration_count: int = 0
    use_mcp: bool = False
    iterative: bool = True
    test_mode: bool = False

    # Skill tracking fields
    session_id: str = ""
    completed_stages: list[str] = field(default_factory=list)
    current_stage: str | None = None
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SkillState":
        """Create from dictionary."""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class StateManager:
    """
    Manages session state and checkpoints for Mali skills.

    Uses LangGraph's SqliteSaver for checkpoint persistence,
    with additional session metadata tracking.
    """

    def __init__(self, checkpoint_path: str | Path | None = None):
        """
        Initialize state manager.

        Args:
            checkpoint_path: Path to SQLite checkpoint database.
                            If None, uses default path.
        """
        if checkpoint_path is None:
            checkpoint_path = Path.cwd() / DEFAULT_CHECKPOINT_PATH

        self.checkpoint_path = Path(checkpoint_path)
        self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize SQLite connection
        self.conn = sqlite3.connect(
            str(self.checkpoint_path),
            check_same_thread=False,
            timeout=30.0,
        )
        self.conn.execute("PRAGMA journal_mode=WAL;")

        # Initialize LangGraph checkpointer
        self.checkpointer = SqliteSaver(self.conn)

        # Initialize session metadata table
        self._init_session_table()

    def _init_session_table(self) -> None:
        """Create session metadata table if it doesn't exist."""
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS mali_sessions (
                session_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                repo TEXT,
                scope TEXT,
                framework TEXT DEFAULT 'drm',
                status TEXT DEFAULT 'running',
                completed_stages TEXT DEFAULT '[]',
                current_stage TEXT,
                extra_metadata TEXT DEFAULT '{}'
            )
        """)
        self.conn.commit()

    def generate_session_id(self, prefix: str = "mali") -> str:
        """
        Generate a unique session ID.

        Args:
            prefix: Prefix for the session ID

        Returns:
            Unique session ID (e.g., "mali-20250115-abc123")
        """
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        unique_suffix = uuid.uuid4().hex[:6]
        return f"{prefix}-{timestamp}-{unique_suffix}"

    def create_session(
        self,
        repo: str,
        scope: str,
        framework: str = "drm",
        session_id: str | None = None,
    ) -> str:
        """
        Create a new analysis session.

        Args:
            repo: Repository path
            scope: Analysis scope (directory)
            framework: Framework type
            session_id: Optional custom session ID

        Returns:
            Session ID
        """
        if session_id is None:
            session_id = self.generate_session_id()

        now = datetime.now().isoformat()

        self.conn.execute(
            """
            INSERT INTO mali_sessions
            (session_id, created_at, updated_at, repo, scope, framework, status, completed_stages, current_stage)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (session_id, now, now, repo, scope, framework, "running", "[]", None),
        )
        self.conn.commit()

        return session_id

    def get_session(self, session_id: str) -> SessionInfo | None:
        """
        Get session metadata.

        Args:
            session_id: Session ID to retrieve

        Returns:
            SessionInfo dict or None if not found
        """
        cursor = self.conn.execute(
            """
            SELECT session_id, created_at, updated_at, repo, scope, framework,
                   status, completed_stages, current_stage
            FROM mali_sessions WHERE session_id = ?
            """,
            (session_id,),
        )
        row = cursor.fetchone()

        if row is None:
            return None

        return SessionInfo(
            session_id=row[0],
            created_at=row[1],
            updated_at=row[2],
            repo=row[3],
            scope=row[4],
            framework=row[5],
            status=row[6],
            completed_stages=json.loads(row[7]),
            current_stage=row[8],
        )

    def update_session(
        self,
        session_id: str,
        status: str | None = None,
        completed_stages: list[str] | None = None,
        current_stage: str | None = None,
    ) -> None:
        """
        Update session metadata.

        Args:
            session_id: Session ID to update
            status: New status (optional)
            completed_stages: Updated completed stages list (optional)
            current_stage: Current stage being executed (optional)
        """
        updates = ["updated_at = ?"]
        values: list[Any] = [datetime.now().isoformat()]

        if status is not None:
            updates.append("status = ?")
            values.append(status)

        if completed_stages is not None:
            updates.append("completed_stages = ?")
            values.append(json.dumps(completed_stages))

        if current_stage is not None:
            updates.append("current_stage = ?")
            values.append(current_stage)

        values.append(session_id)

        self.conn.execute(
            f"UPDATE mali_sessions SET {', '.join(updates)} WHERE session_id = ?",
            values,
        )
        self.conn.commit()

    def mark_stage_completed(self, session_id: str, stage: str) -> None:
        """
        Mark a stage as completed for a session.

        Args:
            session_id: Session ID
            stage: Stage name that was completed
        """
        session = self.get_session(session_id)
        if session is None:
            raise ValueError(f"Session not found: {session_id}")

        completed = session["completed_stages"]
        if stage not in completed:
            completed.append(stage)

        self.update_session(
            session_id,
            completed_stages=completed,
            current_stage=None,
        )

    def list_sessions(
        self,
        status: str | None = None,
        limit: int = 50,
    ) -> list[SessionInfo]:
        """
        List all sessions, optionally filtered by status.

        Args:
            status: Filter by status (optional)
            limit: Maximum number of sessions to return

        Returns:
            List of SessionInfo dicts
        """
        if status:
            cursor = self.conn.execute(
                """
                SELECT session_id, created_at, updated_at, repo, scope, framework,
                       status, completed_stages, current_stage
                FROM mali_sessions
                WHERE status = ?
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (status, limit),
            )
        else:
            cursor = self.conn.execute(
                """
                SELECT session_id, created_at, updated_at, repo, scope, framework,
                       status, completed_stages, current_stage
                FROM mali_sessions
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (limit,),
            )

        sessions = []
        for row in cursor:
            sessions.append(
                SessionInfo(
                    session_id=row[0],
                    created_at=row[1],
                    updated_at=row[2],
                    repo=row[3],
                    scope=row[4],
                    framework=row[5],
                    status=row[6],
                    completed_stages=json.loads(row[7]),
                    current_stage=row[8],
                )
            )
        return sessions

    def delete_session(self, session_id: str) -> bool:
        """
        Delete a session and its checkpoints.

        Args:
            session_id: Session ID to delete

        Returns:
            True if session was deleted, False if not found
        """
        # Check if exists
        session = self.get_session(session_id)
        if session is None:
            return False

        # Delete from session table
        self.conn.execute(
            "DELETE FROM mali_sessions WHERE session_id = ?",
            (session_id,),
        )

        # Delete associated checkpoints (LangGraph uses thread_id)
        # The checkpoint table structure varies by LangGraph version
        try:
            self.conn.execute(
                "DELETE FROM checkpoints WHERE thread_id = ?",
                (session_id,),
            )
        except sqlite3.OperationalError:
            # Table might not exist or have different structure
            pass

        self.conn.commit()
        return True

    def get_checkpointer(self) -> SqliteSaver:
        """Get the LangGraph checkpointer instance."""
        return self.checkpointer

    def get_langgraph_config(self, session_id: str) -> dict[str, Any]:
        """
        Get LangGraph config dict for a session.

        Args:
            session_id: Session ID

        Returns:
            Config dict with thread_id set
        """
        return {"configurable": {"thread_id": session_id}}

    def close(self) -> None:
        """Close database connection."""
        self.conn.close()


# Convenience functions
_default_manager: StateManager | None = None


def get_state_manager(checkpoint_path: str | Path | None = None) -> StateManager:
    """Get or create default state manager instance."""
    global _default_manager
    if _default_manager is None or checkpoint_path is not None:
        _default_manager = StateManager(checkpoint_path)
    return _default_manager


if __name__ == "__main__":
    # Test/demo the state manager
    import sys

    try:
        manager = StateManager()
        print("State Manager initialized successfully")
        print(f"Checkpoint path: {manager.checkpoint_path}")

        # Create test session
        session_id = manager.create_session(
            repo="/test/repo",
            scope="test/scope",
            framework="drm",
        )
        print(f"\nCreated test session: {session_id}")

        # Get session
        session = manager.get_session(session_id)
        print(f"Session info: {session}")

        # Mark stage completed
        manager.mark_stage_completed(session_id, "build_ts_index")
        session = manager.get_session(session_id)
        print(f"After marking stage: {session}")

        # List sessions
        sessions = manager.list_sessions()
        print(f"\nAll sessions: {len(sessions)}")

        # Cleanup test session
        manager.delete_session(session_id)
        print("Test session deleted")

        manager.close()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
