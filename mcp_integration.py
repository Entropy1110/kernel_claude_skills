"""
MCP (Model Context Protocol) Integration for External Tools

Supports integration with:
- IDA Pro (via ida-pro-mcp)
- Ghidra
- Other static analysis tools

This module provides optional enhanced analysis using external tools.
Falls back to local analysis if MCP server is unavailable.

Uses official MCP Python SDK: https://github.com/modelcontextprotocol/python-sdk
"""

import json
import os
import asyncio
from pathlib import Path
from typing import Any
from dataclasses import dataclass

from rich.console import Console

# Official MCP SDK
try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False

console = Console()


@dataclass
class MCPServerConfig:
    """Configuration for an MCP server."""
    name: str
    enabled: bool
    command: str
    args: list[str]
    env: dict[str, str]
    capabilities: list[str]
    timeout: int
    description: str


@dataclass
class MCPAnalysisResult:
    """Result from MCP server analysis."""
    success: bool
    function_info: dict[str, Any] | None = None
    xrefs: list[dict[str, Any]] | None = None
    decompiled_code: str | None = None
    callgraph: dict[str, Any] | None = None
    dataflow: dict[str, Any] | None = None
    error: str | None = None


class MCPIntegration:
    """
    Manages MCP server connections and analysis requests.

    Usage:
        mcp = MCPIntegration()
        if mcp.is_available("ida-pro"):
            result = mcp.analyze_function("ida-pro", file_path, function_name)
    """

    def __init__(self, config_path: str | None = None):
        """
        Initialize MCP integration.

        Args:
            config_path: Path to mcp_config.json (default: configs/mcp_config.json)
        """
        if config_path is None:
            config_path = Path(__file__).parent / "configs" / "mcp_config.json"
        else:
            config_path = Path(config_path)

        self.config_path = config_path
        self.servers: dict[str, MCPServerConfig] = {}
        self.integration_settings = {}
        self.analysis_preferences = {}
        self.cache: dict[str, MCPAnalysisResult] = {}

        self._load_config()

    def _load_config(self):
        """Load MCP configuration from JSON file."""
        if not self.config_path.exists():
            console.print(f"[yellow]MCP config not found at {self.config_path}, MCP disabled[/yellow]")
            return

        try:
            with open(self.config_path) as f:
                config_data = json.load(f)

            # Parse server configs
            for name, server_data in config_data.get("mcp_servers", {}).items():
                # Expand environment variables
                env = {}
                for key, value in server_data.get("env", {}).items():
                    env[key] = os.path.expandvars(value)

                self.servers[name] = MCPServerConfig(
                    name=name,
                    enabled=server_data.get("enabled", False),
                    command=server_data.get("command", ""),
                    args=server_data.get("args", []),
                    env=env,
                    capabilities=server_data.get("capabilities", []),
                    timeout=server_data.get("timeout", 300),
                    description=server_data.get("description", "")
                )

            self.integration_settings = config_data.get("integration_settings", {})
            self.analysis_preferences = config_data.get("analysis_preferences", {})

            # Print enabled servers
            enabled_servers = [name for name, server in self.servers.items() if server.enabled]
            if enabled_servers:
                console.print(f"[green]MCP servers enabled:[/green] {', '.join(enabled_servers)}")
            else:
                console.print("[blue]MCP servers available but not enabled[/blue]")

        except Exception as e:
            console.print(f"[yellow]Failed to load MCP config: {e}[/yellow]")

    def is_available(self, server_name: str) -> bool:
        """Check if MCP server is available and enabled."""
        server = self.servers.get(server_name)
        if not server or not server.enabled:
            return False

        # TODO: Could add health check here (ping server)
        return True

    def get_enabled_servers(self) -> list[str]:
        """Get list of enabled MCP server names."""
        return [name for name, server in self.servers.items() if server.enabled]

    def has_capability(self, server_name: str, capability: str) -> bool:
        """Check if server supports a specific capability."""
        server = self.servers.get(server_name)
        if not server:
            return False
        return capability in server.capabilities

    def analyze_function(
        self,
        server_name: str,
        file_path: str,
        function_name: str,
        capabilities: list[str] | None = None
    ) -> MCPAnalysisResult:
        """
        Analyze a function using specified MCP server.

        Args:
            server_name: Name of MCP server (e.g., "ida-pro")
            file_path: Path to source/binary file
            function_name: Function name to analyze
            capabilities: Requested capabilities (e.g., ["decompile", "xrefs"])

        Returns:
            MCPAnalysisResult with analysis data
        """
        server = self.servers.get(server_name)
        if not server:
            return MCPAnalysisResult(
                success=False,
                error=f"MCP server '{server_name}' not configured"
            )

        if not server.enabled:
            return MCPAnalysisResult(
                success=False,
                error=f"MCP server '{server_name}' is disabled"
            )

        # Check cache
        cache_key = f"{server_name}:{file_path}:{function_name}"
        if self.integration_settings.get("cache_mcp_results", True):
            if cache_key in self.cache:
                console.print(f"[blue]MCP cache hit for {function_name}[/blue]")
                return self.cache[cache_key]

        # Default capabilities if not specified
        if capabilities is None:
            capabilities = ["function_analysis"]
            if self.analysis_preferences.get("prefer_ida_decompiler", True):
                capabilities.append("decompile")
            if self.analysis_preferences.get("use_xrefs_for_callgraph", True):
                capabilities.append("xrefs")

        try:
            result = self._call_mcp_server(server, file_path, function_name, capabilities)

            # Cache result
            if self.integration_settings.get("cache_mcp_results", True):
                self.cache[cache_key] = result

            return result

        except Exception as e:
            console.print(f"[yellow]MCP call failed: {e}[/yellow]")
            return MCPAnalysisResult(
                success=False,
                error=str(e)
            )

    def _call_mcp_server(
        self,
        server: MCPServerConfig,
        file_path: str,
        function_name: str,
        capabilities: list[str]
    ) -> MCPAnalysisResult:
        """
        Make actual MCP server call using official MCP SDK.
        """
        console.print(f"[blue]MCP[/blue] Calling {server.name} for {function_name}")

        if not MCP_AVAILABLE:
            console.print(f"[yellow]MCP SDK not available, using mock data[/yellow]")
            return MCPAnalysisResult(
                success=True,
                function_info={
                    "name": function_name,
                    "address": "0x00000000",
                    "size": 0,
                    "calling_convention": "unknown"
                }
            )

        try:
            # Run async MCP call in sync context
            return asyncio.run(self._async_call_mcp_server(
                server, file_path, function_name, capabilities
            ))
        except Exception as e:
            console.print(f"[red]MCP call failed: {e}[/red]")
            return MCPAnalysisResult(
                success=False,
                error=str(e)
            )

    async def _async_call_mcp_server(
        self,
        server: MCPServerConfig,
        file_path: str,
        function_name: str,
        capabilities: list[str]
    ) -> MCPAnalysisResult:
        """
        Async implementation of MCP server call using official SDK.
        """
        # Create server parameters
        server_params = StdioServerParameters(
            command=server.command,
            args=server.args,
            env=server.env if server.env else None
        )

        result = MCPAnalysisResult(success=True)

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                # Initialize session
                await session.initialize()

                # List available tools
                tools = await session.list_tools()
                available_tools = {tool.name for tool in tools.tools}

                console.print(f"[blue]MCP[/blue] Available tools: {', '.join(available_tools)}")

                # Call tools based on requested capabilities
                if "function_analysis" in capabilities and "analyze_function" in available_tools:
                    analysis_result = await session.call_tool(
                        "analyze_function",
                        arguments={
                            "binary_path": file_path,
                            "function_name": function_name
                        }
                    )
                    if analysis_result.content:
                        # Parse tool result
                        content = analysis_result.content[0]
                        if hasattr(content, 'text'):
                            data = json.loads(content.text)
                            result.function_info = data.get("function_info", {})
                            console.print(f"[green]MCP[/green] Got function info for {function_name}")

                if "decompile" in capabilities and "decompile" in available_tools:
                    decompile_result = await session.call_tool(
                        "decompile",
                        arguments={
                            "binary_path": file_path,
                            "function_name": function_name
                        }
                    )
                    if decompile_result.content:
                        content = decompile_result.content[0]
                        if hasattr(content, 'text'):
                            data = json.loads(content.text)
                            result.decompiled_code = data.get("decompiled_code")
                            console.print(f"[green]MCP[/green] Decompiled {function_name}")

                if "xrefs" in capabilities and "get_xrefs" in available_tools:
                    xrefs_result = await session.call_tool(
                        "get_xrefs",
                        arguments={
                            "binary_path": file_path,
                            "function_name": function_name
                        }
                    )
                    if xrefs_result.content:
                        content = xrefs_result.content[0]
                        if hasattr(content, 'text'):
                            data = json.loads(content.text)
                            result.xrefs = data.get("xrefs", [])
                            console.print(f"[green]MCP[/green] Got {len(result.xrefs)} xrefs for {function_name}")

                # Build callgraph from xrefs
                if "callgraph" in capabilities and result.xrefs:
                    calls = [x for x in result.xrefs if x.get("type") == "call_to"]
                    called_by = [x for x in result.xrefs if x.get("type") == "call_from"]
                    result.callgraph = {
                        "calls": calls,
                        "called_by": called_by
                    }

        return result

    def enrich_candidate_with_mcp(
        self,
        candidate: dict[str, Any],
        preferred_server: str | None = None
    ) -> dict[str, Any]:
        """
        Enrich candidate with MCP analysis results.

        Args:
            candidate: Candidate dict with 'name', 'file', etc.
            preferred_server: Preferred MCP server (default: first enabled)

        Returns:
            Enriched candidate with mcp_analysis field
        """
        if not self.integration_settings.get("use_mcp_for_enrichment", True):
            return candidate

        # Find enabled server
        if preferred_server and self.is_available(preferred_server):
            server_name = preferred_server
        else:
            enabled = self.get_enabled_servers()
            if not enabled:
                return candidate
            server_name = enabled[0]

        # Extract function info
        function_name = candidate.get("name", candidate.get("symbol", ""))
        file_path = candidate.get("file", candidate.get("from_file", ""))

        if not function_name or not file_path:
            return candidate

        # Analyze with MCP
        result = self.analyze_function(server_name, file_path, function_name)

        if result.success:
            candidate["mcp_analysis"] = {
                "server": server_name,
                "function_info": result.function_info,
                "xrefs": result.xrefs,
                "decompiled": result.decompiled_code,
                "callgraph": result.callgraph,
                "dataflow": result.dataflow,
            }
            console.print(f"[green]MCP enriched:[/green] {function_name}")
        else:
            console.print(f"[yellow]MCP enrichment failed for {function_name}: {result.error}[/yellow]")

        return candidate

    def get_decompiled_code(
        self,
        file_path: str,
        function_name: str,
        server_name: str | None = None
    ) -> str | None:
        """
        Get decompiled code for a function.

        Convenience method for getting decompiled code specifically.
        """
        if server_name is None:
            # Use first enabled server with decompile capability
            for name in self.get_enabled_servers():
                if self.has_capability(name, "decompile"):
                    server_name = name
                    break

        if server_name is None:
            return None

        result = self.analyze_function(server_name, file_path, function_name, ["decompile"])

        if result.success:
            return result.decompiled_code

        return None

    def get_xrefs(
        self,
        file_path: str,
        function_name: str,
        server_name: str | None = None
    ) -> list[dict[str, Any]] | None:
        """Get cross-references for a function."""
        if server_name is None:
            for name in self.get_enabled_servers():
                if self.has_capability(name, "xrefs"):
                    server_name = name
                    break

        if server_name is None:
            return None

        result = self.analyze_function(server_name, file_path, function_name, ["xrefs"])

        if result.success:
            max_xrefs = self.analysis_preferences.get("max_xrefs_per_function", 100)
            xrefs = result.xrefs or []
            return xrefs[:max_xrefs]

        return None


# Global singleton instance
_mcp_integration: MCPIntegration | None = None


def get_mcp_integration() -> MCPIntegration:
    """Get global MCP integration instance."""
    global _mcp_integration
    if _mcp_integration is None:
        _mcp_integration = MCPIntegration()
    return _mcp_integration


def is_mcp_enabled() -> bool:
    """Check if any MCP server is enabled."""
    mcp = get_mcp_integration()
    return len(mcp.get_enabled_servers()) > 0
