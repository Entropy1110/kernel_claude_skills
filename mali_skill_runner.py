"""
Mali Skill Runner - Skill Execution Engine for Claude Code

Provides the bridge between Claude Code skills and the LangGraph pipeline.
Each skill invokes specific pipeline stages with checkpoint persistence.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from rich import print
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.sqlite import SqliteSaver

# Import core pipeline components
from mali_static_ai import (
    ScanState,
    build_ts_index,
    map_surface,
    select_candidates,
    enrich_candidates,
    local_triage,
    deep_dive,
    self_critique,
    classify_findings,
    false_positive_classifier,
    iterative_followup,
    write_report,
    need_deep_dive,
    need_critique,
    need_iterative_followup,
    should_continue_iterating,
)
from framework_config import load_framework_config
from mali_llm_factory import LLMFactory, get_factory
from mali_state_manager import StateManager, get_state_manager
from mali_cost_tracker import CostTracker, get_cost_tracker


# Skill definitions with their nodes and prerequisites
SKILL_DEFINITIONS = {
    "map": {
        "nodes": ["build_ts_index", "map_surface", "select_candidates", "enrich_candidates"],
        "prerequisites": [],
        "description": "Build codebase index and identify analysis candidates",
        "output_fields": ["tags", "tags_by_file", "candidates", "entrypoints", "surface_hits"],
    },
    "triage": {
        "nodes": ["local_triage"],
        "prerequisites": ["tags", "candidates"],
        "description": "Quick vulnerability screening with local LLM",
        "output_fields": ["findings"],
    },
    "deep_dive": {
        "nodes": ["deep_dive", "self_critique"],
        "prerequisites": ["findings"],
        "description": "In-depth analysis with Claude",
        "output_fields": ["findings", "deep_dive_notes"],
    },
    "classify": {
        "nodes": ["classify_findings", "false_positive_classifier"],
        "prerequisites": ["findings"],
        "description": "Classify findings as TP/FP/Uncertain",
        "output_fields": ["findings"],
    },
    "followup": {
        "nodes": ["iterative_followup"],
        "prerequisites": ["findings", "tags_by_file"],
        "description": "Iterative follow-up analysis on next_questions",
        "output_fields": ["findings", "analyzed_symbols", "iteration_count"],
    },
    "report": {
        "nodes": ["write_report"],
        "prerequisites": ["findings"],
        "description": "Generate markdown reports",
        "output_fields": ["report_md"],
    },
}

# Stage to completed stages mapping
STAGE_TO_COMPLETED = {
    "build_ts_index": "build_ts_index",
    "map_surface": "map_surface",
    "select_candidates": "select_candidates",
    "enrich_candidates": "enrich_candidates",
    "local_triage": "local_triage",
    "deep_dive": "deep_dive",
    "self_critique": "self_critique",
    "classify_findings": "classify_findings",
    "false_positive_classifier": "false_positive_classifier",
    "iterative_followup": "iterative_followup",
    "write_report": "write_report",
}


@dataclass
class SkillResult:
    """Result from skill execution."""
    success: bool
    session_id: str
    skill_name: str
    output: dict[str, Any]
    error: str | None = None
    cost_summary: dict[str, Any] | None = None


class SkillRunner:
    """
    Executes specific LangGraph skills with checkpoint persistence.

    The main bridge between Claude Code skills and the Mali pipeline.
    """

    def __init__(
        self,
        checkpoint_path: str | Path | None = None,
        config_path: str | Path | None = None,
    ):
        """
        Initialize skill runner.

        Args:
            checkpoint_path: Path to checkpoint database
            config_path: Path to mali-config.json
        """
        # Initialize components
        self.state_manager = get_state_manager(checkpoint_path)
        self.llm_factory = get_factory(config_path)
        self.cost_tracker = get_cost_tracker()

        # Build node function map
        self._node_functions = {
            "build_ts_index": build_ts_index,
            "map_surface": map_surface,
            "select_candidates": select_candidates,
            "enrich_candidates": enrich_candidates,
            "local_triage": local_triage,
            "deep_dive": deep_dive,
            "self_critique": self_critique,
            "classify_findings": classify_findings,
            "false_positive_classifier": false_positive_classifier,
            "iterative_followup": iterative_followup,
            "write_report": write_report,
        }

    def list_skills(self) -> dict[str, dict[str, Any]]:
        """List all available skills with their descriptions."""
        return {
            name: {
                "description": info["description"],
                "prerequisites": info["prerequisites"],
                "nodes": info["nodes"],
            }
            for name, info in SKILL_DEFINITIONS.items()
        }

    def validate_prerequisites(
        self,
        skill_name: str,
        state: dict[str, Any],
    ) -> tuple[bool, list[str]]:
        """
        Validate that prerequisites are met for a skill.

        Args:
            skill_name: Name of skill to validate
            state: Current state dict

        Returns:
            Tuple of (is_valid, missing_fields)
        """
        if skill_name not in SKILL_DEFINITIONS:
            return False, [f"Unknown skill: {skill_name}"]

        skill_def = SKILL_DEFINITIONS[skill_name]
        prerequisites = skill_def["prerequisites"]

        missing = []
        for field in prerequisites:
            value = state.get(field)
            if value is None or (isinstance(value, (list, dict)) and len(value) == 0):
                missing.append(field)

        return len(missing) == 0, missing

    def _build_skill_graph(
        self,
        skill_name: str,
    ) -> StateGraph:
        """
        Build a LangGraph for a specific skill.

        Args:
            skill_name: Name of skill to build graph for

        Returns:
            Compiled StateGraph
        """
        if skill_name not in SKILL_DEFINITIONS:
            raise ValueError(f"Unknown skill: {skill_name}")

        skill_def = SKILL_DEFINITIONS[skill_name]
        nodes = skill_def["nodes"]

        g = StateGraph(ScanState)

        # Add nodes for this skill
        for node_name in nodes:
            if node_name not in self._node_functions:
                raise ValueError(f"Unknown node: {node_name}")
            g.add_node(node_name, self._node_functions[node_name])

        # Build linear edges for the skill
        if len(nodes) == 1:
            g.add_edge(START, nodes[0])
            g.add_edge(nodes[0], END)
        else:
            g.add_edge(START, nodes[0])
            for i in range(len(nodes) - 1):
                g.add_edge(nodes[i], nodes[i + 1])
            g.add_edge(nodes[-1], END)

        return g.compile(checkpointer=self.state_manager.get_checkpointer())

    def run_skill(
        self,
        skill_name: Literal["map", "triage", "deep_dive", "classify", "followup", "report"],
        session_id: str,
        repo: str | None = None,
        scope: str | None = None,
        framework: str = "drm",
        llm_override: dict[str, str] | None = None,
        test_mode: bool = False,
        use_mcp: bool = False,
        iterative_mode: bool = True,
        **kwargs: Any,
    ) -> SkillResult:
        """
        Run a specific skill for a session.

        Args:
            skill_name: Name of skill to run
            session_id: Session ID (creates new if not exists)
            repo: Repository path (required for new sessions)
            scope: Analysis scope (required for new sessions)
            framework: Framework type (drm, generic, application)
            llm_override: Optional LLM model override
            test_mode: Enable test mode
            use_mcp: Enable MCP integration
            iterative_mode: Enable iterative follow-up
            **kwargs: Additional arguments

        Returns:
            SkillResult with output data
        """
        print(f"[cyan]Running skill:[/cyan] {skill_name}")
        print(f"[cyan]Session:[/cyan] {session_id}")

        try:
            # Get or create session
            session = self.state_manager.get_session(session_id)

            if session is None:
                # New session - require repo and scope
                if not repo or not scope:
                    return SkillResult(
                        success=False,
                        session_id=session_id,
                        skill_name=skill_name,
                        output={},
                        error="New session requires --repo and --scope arguments",
                    )

                # Create session
                self.state_manager.create_session(
                    repo=os.path.abspath(repo),
                    scope=scope,
                    framework=framework,
                    session_id=session_id,
                )
                session = self.state_manager.get_session(session_id)

                # Initialize state
                framework_config = load_framework_config(framework)
                state: ScanState = {
                    "repo": os.path.abspath(repo),
                    "scope": scope,
                    "test_mode": test_mode,
                    "thread_id": session_id,
                    "framework": framework,
                    "framework_config": framework_config,
                    "iterative_mode": iterative_mode,
                    "analyzed_symbols": [],
                    "iteration_count": 0,
                    "use_mcp": use_mcp,
                    "surface_hits": [],
                    "tags": [],
                    "tags_by_file": {},
                    "candidates": [],
                    "findings": [],
                    "entrypoints": [],
                    "deep_dive_notes": {},
                    "report_md": "",
                }
                print(f"[green]Created new session:[/green] {session_id}")
            else:
                # Existing session - load state from checkpoint
                print(f"[blue]Resuming session:[/blue] {session_id}")
                state = self._load_state_from_checkpoint(session_id, session)

            # Validate prerequisites
            is_valid, missing = self.validate_prerequisites(skill_name, state)
            if not is_valid:
                return SkillResult(
                    success=False,
                    session_id=session_id,
                    skill_name=skill_name,
                    output={},
                    error=f"Missing prerequisites: {', '.join(missing)}. "
                          f"Run earlier skills first (e.g., mali-map, mali-triage).",
                )

            # Update session status
            self.state_manager.update_session(
                session_id,
                status="running",
                current_stage=skill_name,
            )

            # Build and run skill graph
            print(f"[yellow]Executing {skill_name} nodes...[/yellow]")
            graph = self._build_skill_graph(skill_name)
            config = self.state_manager.get_langgraph_config(session_id)

            # Run the graph
            result_state = graph.invoke(state, config)

            # Mark stages as completed
            skill_def = SKILL_DEFINITIONS[skill_name]
            completed_stages = session["completed_stages"] if session else []
            for node in skill_def["nodes"]:
                if node not in completed_stages:
                    completed_stages.append(node)

            self.state_manager.update_session(
                session_id,
                status="paused",
                completed_stages=completed_stages,
                current_stage=None,
            )

            # Prepare output
            output_fields = skill_def["output_fields"]
            output = {field: result_state.get(field) for field in output_fields}

            # Add summary info
            output["_summary"] = self._generate_summary(skill_name, result_state)

            # Get cost summary if available
            cost_summary = self.cost_tracker.get_session_cost(session_id)

            print(f"[green]Skill {skill_name} completed successfully![/green]")

            return SkillResult(
                success=True,
                session_id=session_id,
                skill_name=skill_name,
                output=output,
                cost_summary=cost_summary,
            )

        except Exception as e:
            import traceback
            error_msg = f"{type(e).__name__}: {e}"
            print(f"[red]Error running skill {skill_name}:[/red] {error_msg}")
            traceback.print_exc()

            # Update session status
            try:
                self.state_manager.update_session(session_id, status="failed")
            except Exception:
                pass

            return SkillResult(
                success=False,
                session_id=session_id,
                skill_name=skill_name,
                output={},
                error=error_msg,
            )

    def _load_state_from_checkpoint(
        self,
        session_id: str,
        session: dict[str, Any],
    ) -> ScanState:
        """Load state from checkpoint, rebuilding framework_config."""
        # Get checkpoint state via LangGraph
        checkpointer = self.state_manager.get_checkpointer()
        config = self.state_manager.get_langgraph_config(session_id)

        # Try to get latest checkpoint
        checkpoint = checkpointer.get(config)

        if checkpoint and checkpoint.get("channel_values"):
            state = dict(checkpoint["channel_values"])
        else:
            # Initialize from session metadata
            framework_config = load_framework_config(session["framework"])
            state = {
                "repo": session["repo"],
                "scope": session["scope"],
                "test_mode": False,
                "thread_id": session_id,
                "framework": session["framework"],
                "framework_config": framework_config,
                "iterative_mode": True,
                "analyzed_symbols": [],
                "iteration_count": 0,
                "use_mcp": False,
                "surface_hits": [],
                "tags": [],
                "tags_by_file": {},
                "candidates": [],
                "findings": [],
                "entrypoints": [],
                "deep_dive_notes": {},
                "report_md": "",
            }

        # Ensure framework_config is loaded (not serializable)
        if "framework_config" not in state or state["framework_config"] is None:
            state["framework_config"] = load_framework_config(session["framework"])

        return state

    def _generate_summary(
        self,
        skill_name: str,
        state: dict[str, Any],
    ) -> dict[str, Any]:
        """Generate a summary of the skill execution."""
        summary = {"skill": skill_name, "timestamp": datetime.now().isoformat()}

        if skill_name == "map":
            summary["files_indexed"] = len(state.get("tags", []))
            summary["candidates_found"] = len(state.get("candidates", []))
            summary["entrypoints_found"] = len(state.get("entrypoints", []))
            summary["surface_hits"] = len(state.get("surface_hits", []))

        elif skill_name == "triage":
            findings = state.get("findings", [])
            summary["findings_count"] = len(findings)
            summary["high_risk"] = sum(1 for f in findings
                                       if f.get("risk", "").lower() == "high")
            summary["medium_risk"] = sum(1 for f in findings
                                         if f.get("risk", "").lower() == "medium")
            summary["low_risk"] = sum(1 for f in findings
                                      if f.get("risk", "").lower() == "low")

        elif skill_name == "deep_dive":
            findings = state.get("findings", [])
            summary["findings_analyzed"] = len(findings)
            summary["with_deep_analysis"] = sum(1 for f in findings
                                                if f.get("deep_analysis"))

        elif skill_name == "classify":
            findings = state.get("findings", [])
            summary["total_findings"] = len(findings)
            summary["true_positives"] = sum(1 for f in findings
                                            if f.get("classification") == "true_positive")
            summary["false_positives"] = sum(1 for f in findings
                                             if f.get("classification") == "false_positive")
            summary["uncertain"] = sum(1 for f in findings
                                       if f.get("classification") == "uncertain")

        elif skill_name == "followup":
            summary["iteration_count"] = state.get("iteration_count", 0)
            summary["symbols_analyzed"] = len(state.get("analyzed_symbols", []))

        elif skill_name == "report":
            summary["report_generated"] = bool(state.get("report_md"))
            summary["output_files"] = ["out/report.md", "out/report_true_positives.md", "out/state.json"]

        return summary

    def run_full_pipeline(
        self,
        repo: str,
        scope: str,
        framework: str = "drm",
        session_id: str | None = None,
        test_mode: bool = False,
        use_mcp: bool = False,
        iterative_mode: bool = True,
        **kwargs: Any,
    ) -> SkillResult:
        """
        Run the complete analysis pipeline.

        Args:
            repo: Repository path
            scope: Analysis scope
            framework: Framework type
            session_id: Optional session ID
            test_mode: Enable test mode
            use_mcp: Enable MCP integration
            iterative_mode: Enable iterative follow-up

        Returns:
            SkillResult with final output
        """
        from mali_static_ai import build_app

        print("[bold cyan]Running full analysis pipeline[/bold cyan]")

        # Generate session ID if not provided
        if session_id is None:
            session_id = self.state_manager.generate_session_id()

        print(f"[cyan]Session:[/cyan] {session_id}")
        print(f"[cyan]Repository:[/cyan] {repo}")
        print(f"[cyan]Scope:[/cyan] {scope}")
        print(f"[cyan]Framework:[/cyan] {framework}")

        try:
            # Create session
            self.state_manager.create_session(
                repo=os.path.abspath(repo),
                scope=scope,
                framework=framework,
                session_id=session_id,
            )

            # Load framework config
            framework_config = load_framework_config(framework)
            print(f"[green]Loaded framework:[/green] {framework_config.display_name}")

            # Initialize state
            init_state: ScanState = {
                "repo": os.path.abspath(repo),
                "scope": scope,
                "test_mode": test_mode,
                "thread_id": session_id,
                "framework": framework,
                "framework_config": framework_config,
                "iterative_mode": iterative_mode,
                "analyzed_symbols": [],
                "iteration_count": 0,
                "use_mcp": use_mcp,
                "surface_hits": [],
                "tags": [],
                "tags_by_file": {},
                "candidates": [],
                "findings": [],
                "entrypoints": [],
                "deep_dive_notes": {},
                "report_md": "",
            }

            # Update session status
            self.state_manager.update_session(session_id, status="running")

            # Build and run full app
            app = build_app()
            config = {"configurable": {"thread_id": session_id}}

            final_state = app.invoke(init_state, config)

            # Update session
            self.state_manager.update_session(
                session_id,
                status="completed",
                completed_stages=list(STAGE_TO_COMPLETED.values()),
            )

            # Get cost summary
            cost_summary = self.cost_tracker.get_session_cost(session_id)

            print("[bold green]Analysis complete![/bold green]")
            print(f"[blue]Generated reports:[/blue]")
            print(f"  - out/report.md (all findings)")
            print(f"  - out/report_true_positives.md (FPs filtered)")
            print(f"  - out/state.json")

            return SkillResult(
                success=True,
                session_id=session_id,
                skill_name="full_pipeline",
                output={
                    "findings_count": len(final_state.get("findings", [])),
                    "report_md": final_state.get("report_md", ""),
                    "_summary": {
                        "completed": True,
                        "output_files": [
                            "out/report.md",
                            "out/report_true_positives.md",
                            "out/state.json",
                        ],
                    },
                },
                cost_summary=cost_summary,
            )

        except Exception as e:
            import traceback
            error_msg = f"{type(e).__name__}: {e}"
            print(f"[red]Pipeline error:[/red] {error_msg}")
            traceback.print_exc()

            try:
                self.state_manager.update_session(session_id, status="failed")
            except Exception:
                pass

            return SkillResult(
                success=False,
                session_id=session_id,
                skill_name="full_pipeline",
                output={},
                error=error_msg,
            )

    def list_sessions(self, status: str | None = None) -> list[dict[str, Any]]:
        """List all sessions."""
        return self.state_manager.list_sessions(status=status)

    def get_session_info(self, session_id: str) -> dict[str, Any] | None:
        """Get info about a specific session."""
        session = self.state_manager.get_session(session_id)
        if session:
            cost = self.cost_tracker.get_session_cost(session_id)
            return {**session, "cost": cost}
        return None

    def delete_session(self, session_id: str) -> bool:
        """Delete a session and its data."""
        self.cost_tracker.clear_session(session_id)
        return self.state_manager.delete_session(session_id)


def main():
    """CLI entry point for skill runner."""
    parser = argparse.ArgumentParser(
        description="Mali Skill Runner - Execute Mali analysis skills"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # run-skill command
    skill_parser = subparsers.add_parser(
        "run-skill",
        help="Run a specific skill",
    )
    skill_parser.add_argument(
        "skill_name",
        choices=list(SKILL_DEFINITIONS.keys()),
        help="Skill to run",
    )
    skill_parser.add_argument(
        "--session-id",
        required=True,
        help="Session ID (creates new if not exists)",
    )
    skill_parser.add_argument("--repo", help="Repository path (required for new sessions)")
    skill_parser.add_argument("--scope", help="Analysis scope (required for new sessions)")
    skill_parser.add_argument(
        "--framework",
        default="drm",
        choices=["drm", "generic", "application", "mali"],
        help="Framework type",
    )
    skill_parser.add_argument("--llm-model", help="Override LLM model")
    skill_parser.add_argument("--test", action="store_true", help="Enable test mode")
    skill_parser.add_argument("--use-mcp", action="store_true", help="Enable MCP integration")
    skill_parser.add_argument(
        "--no-iterative",
        action="store_false",
        dest="iterative",
        help="Disable iterative follow-up",
    )

    # run-full-pipeline command
    pipeline_parser = subparsers.add_parser(
        "run-full-pipeline",
        help="Run complete analysis pipeline",
    )
    pipeline_parser.add_argument("--repo", required=True, help="Repository path")
    pipeline_parser.add_argument("--scope", required=True, help="Analysis scope")
    pipeline_parser.add_argument(
        "--framework",
        default="drm",
        choices=["drm", "generic", "application", "mali"],
        help="Framework type",
    )
    pipeline_parser.add_argument("--session-id", help="Optional session ID")
    pipeline_parser.add_argument("--test", action="store_true", help="Enable test mode")
    pipeline_parser.add_argument("--use-mcp", action="store_true", help="Enable MCP integration")
    pipeline_parser.add_argument(
        "--no-iterative",
        action="store_false",
        dest="iterative",
        help="Disable iterative follow-up",
    )

    # list-sessions command
    list_parser = subparsers.add_parser("list-sessions", help="List all sessions")
    list_parser.add_argument("--status", help="Filter by status")

    # session-info command
    info_parser = subparsers.add_parser("session-info", help="Get session info")
    info_parser.add_argument("session_id", help="Session ID")

    # delete-session command
    delete_parser = subparsers.add_parser("delete-session", help="Delete a session")
    delete_parser.add_argument("session_id", help="Session ID to delete")

    # list-skills command
    subparsers.add_parser("list-skills", help="List available skills")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    runner = SkillRunner()

    if args.command == "run-skill":
        llm_override = {"model": args.llm_model} if args.llm_model else None
        result = runner.run_skill(
            skill_name=args.skill_name,
            session_id=args.session_id,
            repo=args.repo,
            scope=args.scope,
            framework=args.framework,
            llm_override=llm_override,
            test_mode=args.test,
            use_mcp=args.use_mcp,
            iterative_mode=args.iterative,
        )

        # Output result
        output = {
            "success": result.success,
            "session_id": result.session_id,
            "skill": result.skill_name,
            "error": result.error,
        }
        if result.success:
            output["summary"] = result.output.get("_summary", {})
            if result.cost_summary:
                output["cost"] = result.cost_summary

        print("\n[bold]Result:[/bold]")
        print(json.dumps(output, indent=2, default=str))

        sys.exit(0 if result.success else 1)

    elif args.command == "run-full-pipeline":
        result = runner.run_full_pipeline(
            repo=args.repo,
            scope=args.scope,
            framework=args.framework,
            session_id=args.session_id,
            test_mode=args.test,
            use_mcp=args.use_mcp,
            iterative_mode=args.iterative,
        )

        output = {
            "success": result.success,
            "session_id": result.session_id,
            "error": result.error,
        }
        if result.success:
            output["summary"] = result.output.get("_summary", {})
            if result.cost_summary:
                output["cost"] = result.cost_summary

        print("\n[bold]Result:[/bold]")
        print(json.dumps(output, indent=2, default=str))

        sys.exit(0 if result.success else 1)

    elif args.command == "list-sessions":
        sessions = runner.list_sessions(status=args.status)
        print(json.dumps(sessions, indent=2, default=str))

    elif args.command == "session-info":
        info = runner.get_session_info(args.session_id)
        if info:
            print(json.dumps(info, indent=2, default=str))
        else:
            print(f"Session not found: {args.session_id}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "delete-session":
        if runner.delete_session(args.session_id):
            print(f"Deleted session: {args.session_id}")
        else:
            print(f"Session not found: {args.session_id}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "list-skills":
        skills = runner.list_skills()
        print(json.dumps(skills, indent=2))


if __name__ == "__main__":
    main()
