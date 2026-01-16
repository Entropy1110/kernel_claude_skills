"""
Cost Tracking for Mali Static AI Skills

Tracks LLM API usage and costs across analysis sessions.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


# Default cost log path
DEFAULT_COST_LOG_PATH = ".claude/state/mali-state/cost_log.json"

# Default pricing (per 1K tokens)
DEFAULT_PRICING = {
    "anthropic/claude-sonnet-4": {"input": 0.003, "output": 0.015},
    "anthropic/claude-opus-4": {"input": 0.015, "output": 0.075},
    "anthropic/claude-3.5-sonnet": {"input": 0.003, "output": 0.015},
    "anthropic/claude-3-opus": {"input": 0.015, "output": 0.075},
    "ollama": {"input": 0.0, "output": 0.0},  # Local models are free
}


@dataclass
class UsageEntry:
    """Single API usage entry."""
    timestamp: str
    session_id: str
    stage: str
    model: str
    provider: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    duration_ms: int | None = None
    error: str | None = None


class CostTracker:
    """
    Tracks LLM API costs across sessions.

    Stores usage data in a JSON log file for easy inspection and analysis.
    """

    def __init__(
        self,
        log_path: str | Path | None = None,
        pricing: dict[str, dict[str, float]] | None = None,
    ):
        """
        Initialize cost tracker.

        Args:
            log_path: Path to JSON log file. If None, uses default path.
            pricing: Custom pricing dict. If None, uses default pricing.
        """
        if log_path is None:
            log_path = Path.cwd() / DEFAULT_COST_LOG_PATH

        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        self.pricing = pricing or DEFAULT_PRICING
        self._entries: list[dict[str, Any]] | None = None

    def _load_entries(self) -> list[dict[str, Any]]:
        """Load entries from log file."""
        if self._entries is not None:
            return self._entries

        if self.log_path.exists():
            try:
                with open(self.log_path, encoding="utf-8") as f:
                    self._entries = json.load(f)
            except (json.JSONDecodeError, IOError):
                self._entries = []
        else:
            self._entries = []

        return self._entries

    def _save_entries(self) -> None:
        """Save entries to log file."""
        if self._entries is None:
            return

        with open(self.log_path, "w", encoding="utf-8") as f:
            json.dump(self._entries, f, indent=2)

    def calculate_cost(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
    ) -> float:
        """
        Calculate cost for a given model and token counts.

        Args:
            model: Model name (e.g., "anthropic/claude-sonnet-4")
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens

        Returns:
            Cost in USD
        """
        # Check for exact model match
        if model in self.pricing:
            price_info = self.pricing[model]
        elif "ollama" in model.lower() or model.startswith("qwen"):
            price_info = self.pricing.get("ollama", {"input": 0, "output": 0})
        else:
            # Default to Claude Sonnet pricing
            price_info = self.pricing.get(
                "anthropic/claude-sonnet-4",
                {"input": 0.003, "output": 0.015}
            )

        input_cost = (input_tokens / 1000) * price_info.get("input", 0)
        output_cost = (output_tokens / 1000) * price_info.get("output", 0)

        return round(input_cost + output_cost, 6)

    def log_usage(
        self,
        session_id: str,
        stage: str,
        model: str,
        provider: str,
        input_tokens: int,
        output_tokens: int,
        duration_ms: int | None = None,
        error: str | None = None,
    ) -> UsageEntry:
        """
        Log an API usage event.

        Args:
            session_id: Analysis session ID
            stage: Pipeline stage (e.g., "deep_dive")
            model: Model name used
            provider: Provider ("ollama", "openrouter", "anthropic")
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            duration_ms: Optional request duration in milliseconds
            error: Optional error message if request failed

        Returns:
            UsageEntry with calculated cost
        """
        cost = self.calculate_cost(model, input_tokens, output_tokens)

        entry = UsageEntry(
            timestamp=datetime.now().isoformat(),
            session_id=session_id,
            stage=stage,
            model=model,
            provider=provider,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost,
            duration_ms=duration_ms,
            error=error,
        )

        entries = self._load_entries()
        entries.append({
            "timestamp": entry.timestamp,
            "session_id": entry.session_id,
            "stage": entry.stage,
            "model": entry.model,
            "provider": entry.provider,
            "input_tokens": entry.input_tokens,
            "output_tokens": entry.output_tokens,
            "cost_usd": entry.cost_usd,
            "duration_ms": entry.duration_ms,
            "error": entry.error,
        })
        self._save_entries()

        return entry

    def get_session_cost(self, session_id: str) -> dict[str, Any]:
        """
        Get total cost and breakdown for a session.

        Args:
            session_id: Session ID to query

        Returns:
            Dict with total cost and breakdown by stage
        """
        entries = self._load_entries()
        session_entries = [e for e in entries if e.get("session_id") == session_id]

        total_cost = sum(e.get("cost_usd", 0) for e in session_entries)
        total_input = sum(e.get("input_tokens", 0) for e in session_entries)
        total_output = sum(e.get("output_tokens", 0) for e in session_entries)

        # Breakdown by stage
        by_stage: dict[str, dict[str, Any]] = {}
        for entry in session_entries:
            stage = entry.get("stage", "unknown")
            if stage not in by_stage:
                by_stage[stage] = {
                    "cost_usd": 0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "calls": 0,
                }
            by_stage[stage]["cost_usd"] += entry.get("cost_usd", 0)
            by_stage[stage]["input_tokens"] += entry.get("input_tokens", 0)
            by_stage[stage]["output_tokens"] += entry.get("output_tokens", 0)
            by_stage[stage]["calls"] += 1

        return {
            "session_id": session_id,
            "total_cost_usd": round(total_cost, 4),
            "total_input_tokens": total_input,
            "total_output_tokens": total_output,
            "total_calls": len(session_entries),
            "by_stage": by_stage,
        }

    def get_total_cost(self, since: str | None = None) -> dict[str, Any]:
        """
        Get total cost across all sessions.

        Args:
            since: Optional ISO timestamp to filter entries from

        Returns:
            Dict with total cost and breakdown by session
        """
        entries = self._load_entries()

        if since:
            entries = [e for e in entries if e.get("timestamp", "") >= since]

        total_cost = sum(e.get("cost_usd", 0) for e in entries)
        total_input = sum(e.get("input_tokens", 0) for e in entries)
        total_output = sum(e.get("output_tokens", 0) for e in entries)

        # Breakdown by session
        by_session: dict[str, float] = {}
        for entry in entries:
            session_id = entry.get("session_id", "unknown")
            by_session[session_id] = by_session.get(session_id, 0) + entry.get("cost_usd", 0)

        return {
            "total_cost_usd": round(total_cost, 4),
            "total_input_tokens": total_input,
            "total_output_tokens": total_output,
            "total_calls": len(entries),
            "by_session": {k: round(v, 4) for k, v in by_session.items()},
        }

    def get_session_history(
        self,
        session_id: str,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """
        Get usage history for a session.

        Args:
            session_id: Session ID to query
            limit: Optional limit on number of entries

        Returns:
            List of usage entries
        """
        entries = self._load_entries()
        session_entries = [e for e in entries if e.get("session_id") == session_id]

        # Sort by timestamp descending
        session_entries.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

        if limit:
            session_entries = session_entries[:limit]

        return session_entries

    def clear_session(self, session_id: str) -> int:
        """
        Clear all usage entries for a session.

        Args:
            session_id: Session ID to clear

        Returns:
            Number of entries deleted
        """
        entries = self._load_entries()
        original_count = len(entries)
        self._entries = [e for e in entries if e.get("session_id") != session_id]
        self._save_entries()

        return original_count - len(self._entries)

    def format_cost_summary(self, session_id: str) -> str:
        """
        Format a human-readable cost summary for a session.

        Args:
            session_id: Session ID

        Returns:
            Formatted summary string
        """
        summary = self.get_session_cost(session_id)

        lines = [
            f"Cost Summary for Session: {session_id}",
            f"{'=' * 50}",
            f"Total Cost: ${summary['total_cost_usd']:.4f} USD",
            f"Total Input Tokens: {summary['total_input_tokens']:,}",
            f"Total Output Tokens: {summary['total_output_tokens']:,}",
            f"Total API Calls: {summary['total_calls']}",
            "",
            "Breakdown by Stage:",
        ]

        for stage, data in summary["by_stage"].items():
            lines.append(
                f"  {stage}: ${data['cost_usd']:.4f} "
                f"({data['input_tokens']:,} in / {data['output_tokens']:,} out, "
                f"{data['calls']} calls)"
            )

        return "\n".join(lines)


# Convenience functions
_default_tracker: CostTracker | None = None


def get_cost_tracker(log_path: str | Path | None = None) -> CostTracker:
    """Get or create default cost tracker instance."""
    global _default_tracker
    if _default_tracker is None or log_path is not None:
        _default_tracker = CostTracker(log_path)
    return _default_tracker


def log_usage(
    session_id: str,
    stage: str,
    model: str,
    provider: str,
    input_tokens: int,
    output_tokens: int,
    **kwargs: Any,
) -> UsageEntry:
    """Convenience function to log usage."""
    tracker = get_cost_tracker()
    return tracker.log_usage(
        session_id=session_id,
        stage=stage,
        model=model,
        provider=provider,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        **kwargs,
    )


if __name__ == "__main__":
    # Test/demo the cost tracker
    import sys

    try:
        tracker = CostTracker()
        print("Cost Tracker initialized successfully")
        print(f"Log path: {tracker.log_path}")

        # Test cost calculation
        cost = tracker.calculate_cost(
            "anthropic/claude-sonnet-4",
            input_tokens=1000,
            output_tokens=500,
        )
        print(f"\nCost for 1K input + 500 output tokens (Sonnet): ${cost:.4f}")

        # Log test usage
        test_session = "test-session-001"
        entry = tracker.log_usage(
            session_id=test_session,
            stage="deep_dive",
            model="anthropic/claude-sonnet-4",
            provider="openrouter",
            input_tokens=5000,
            output_tokens=2000,
            duration_ms=3500,
        )
        print(f"\nLogged test entry: ${entry.cost_usd:.4f}")

        # Get session summary
        summary = tracker.get_session_cost(test_session)
        print(f"\nSession summary: {summary}")

        # Format summary
        print(f"\n{tracker.format_cost_summary(test_session)}")

        # Cleanup
        deleted = tracker.clear_session(test_session)
        print(f"\nCleaned up {deleted} test entries")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
