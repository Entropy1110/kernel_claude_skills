"""
Framework Configuration System

Provides pluggable framework definitions for domain-specific static analysis.
Frameworks are defined in YAML files under configs/ directory.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List
import yaml


@dataclass
class LifecycleStage:
    """Represents a stage in a framework's lifecycle."""
    name: str
    functions: List[str]
    description: str


@dataclass
class EntrypointPattern:
    """Pattern for detecting framework entrypoints."""
    regex: str
    field: str
    name_pattern: str | None = None


@dataclass
class FalsePositiveRule:
    """Rule for filtering false positive findings."""
    pattern: str
    reason: str
    auto_downgrade: bool
    target_risk: str


@dataclass
class FrameworkConfig:
    """Complete framework configuration loaded from YAML."""
    name: str
    display_name: str
    lifecycle_stages: List[LifecycleStage]
    lifecycle_guarantees: List[str]
    entrypoint_patterns: Dict[str, List[EntrypointPattern]]
    indicator_patterns: Dict[str, List[str]]
    false_positive_rules: List[FalsePositiveRule]
    prompt_role: str
    framework_knowledge: str
    false_positive_examples: List[Dict[str, str]] = field(default_factory=list)


class FrameworkRegistry:
    """Registry for loading and caching framework configurations."""

    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.configs: Dict[str, FrameworkConfig] = {}

    def load_config(self, framework_name: str) -> FrameworkConfig:
        """
        Load and parse framework YAML config.

        Args:
            framework_name: Name of framework (e.g., "drm", "generic")

        Returns:
            Parsed FrameworkConfig

        Raises:
            ValueError: If framework config not found or invalid
        """
        # Check cache first
        if framework_name in self.configs:
            return self.configs[framework_name]

        config_path = self.config_dir / f"{framework_name}.yaml"
        if not config_path.exists():
            available = self.list_frameworks()
            raise ValueError(
                f"Framework '{framework_name}' not found. "
                f"Available: {', '.join(available)}"
            )

        try:
            with open(config_path, encoding="utf-8") as f:
                data = yaml.safe_load(f)

            config = self._parse_config(data)

            # Cache for future use
            self.configs[framework_name] = config

            return config

        except yaml.YAMLError as e:
            raise ValueError(f"Failed to parse {config_path}: {e}") from e
        except (KeyError, TypeError) as e:
            raise ValueError(f"Invalid config structure in {config_path}: {e}") from e

    def _parse_config(self, data: Dict[str, Any]) -> FrameworkConfig:
        """Parse YAML data into FrameworkConfig dataclass."""

        # Parse lifecycle stages
        stages = [
            LifecycleStage(
                name=s["name"],
                functions=s["functions"],
                description=s["description"]
            )
            for s in data["lifecycle"]["stages"]
        ]

        # Parse entrypoint patterns
        entrypoint_patterns = {}
        for category, patterns in data["entrypoint_patterns"].items():
            entrypoint_patterns[category] = [
                EntrypointPattern(
                    regex=p["regex"],
                    field=p["field"],
                    name_pattern=p.get("name_pattern")
                )
                for p in patterns
            ]

        # Parse false positive rules
        fp_rules = [
            FalsePositiveRule(
                pattern=r["pattern"],
                reason=r["reason"],
                auto_downgrade=r["auto_downgrade"],
                target_risk=r["target_risk"]
            )
            for r in data.get("false_positive_rules", [])
        ]

        # Parse false positive examples (optional)
        fp_examples = []
        for ex in data.get("prompt_context", {}).get("false_positive_examples", []):
            fp_examples.append({
                "title": ex["title"],
                "code": ex["code"],
                "wrong_analysis": ex["wrong_analysis"],
                "correct_analysis": ex["correct_analysis"],
                "key_insight": ex["key_insight"]
            })

        return FrameworkConfig(
            name=data["framework"]["name"],
            display_name=data["framework"]["display_name"],
            lifecycle_stages=stages,
            lifecycle_guarantees=data["lifecycle"]["guarantees"],
            entrypoint_patterns=entrypoint_patterns,
            indicator_patterns=data["indicator_patterns"],
            false_positive_rules=fp_rules,
            prompt_role=data["prompt_context"]["role"],
            framework_knowledge=data["prompt_context"]["framework_knowledge"],
            false_positive_examples=fp_examples
        )

    def list_frameworks(self) -> List[str]:
        """List all available framework configurations."""
        if not self.config_dir.exists():
            return []
        return [p.stem for p in self.config_dir.glob("*.yaml")]


# Global registry instance
_registry: FrameworkRegistry | None = None


def get_framework_registry() -> FrameworkRegistry:
    """Get or create the global framework registry."""
    global _registry
    if _registry is None:
        config_dir = Path(__file__).parent / "configs"
        config_dir.mkdir(exist_ok=True)  # Ensure configs dir exists
        _registry = FrameworkRegistry(config_dir)
    return _registry


def load_framework_config(framework_name: str) -> FrameworkConfig:
    """
    Public API to load framework configuration.

    Args:
        framework_name: Name of framework (e.g., "drm", "generic")

    Returns:
        Loaded FrameworkConfig

    Raises:
        ValueError: If framework not found or invalid

    Example:
        >>> config = load_framework_config("drm")
        >>> print(config.display_name)
        DRM/GPU Drivers
    """
    return get_framework_registry().load_config(framework_name)


def load_framework_config_with_overrides(
    framework_name: str,
    overrides: Dict[str, Any] | None = None,
) -> FrameworkConfig:
    """
    Load framework configuration with optional overrides.

    Allows skill users to customize framework behavior without
    modifying the base YAML files.

    Args:
        framework_name: Name of base framework (e.g., "drm", "generic")
        overrides: Optional dict of overrides to apply. Supported keys:
            - "indicator_patterns": Dict to merge with existing patterns
            - "false_positive_rules": List of additional FP rules
            - "prompt_role": Override the prompt role
            - "framework_knowledge": Additional framework knowledge to append

    Returns:
        FrameworkConfig with overrides applied

    Example:
        >>> config = load_framework_config_with_overrides(
        ...     "drm",
        ...     overrides={
        ...         "indicator_patterns": {
        ...             "user_control": ["custom_user_func"],
        ...         },
        ...         "false_positive_rules": [
        ...             {
        ...                 "pattern": "custom_safe_pattern",
        ...                 "reason": "Custom safety guarantee",
        ...                 "auto_downgrade": True,
        ...                 "target_risk": "low"
        ...             }
        ...         ]
        ...     }
        ... )
    """
    import copy

    # Load base config
    base_config = load_framework_config(framework_name)

    if not overrides:
        return base_config

    # Create a mutable copy
    config_dict = {
        "name": base_config.name,
        "display_name": base_config.display_name,
        "lifecycle_stages": base_config.lifecycle_stages,
        "lifecycle_guarantees": base_config.lifecycle_guarantees,
        "entrypoint_patterns": copy.deepcopy(base_config.entrypoint_patterns),
        "indicator_patterns": copy.deepcopy(base_config.indicator_patterns),
        "false_positive_rules": list(base_config.false_positive_rules),
        "prompt_role": base_config.prompt_role,
        "framework_knowledge": base_config.framework_knowledge,
        "false_positive_examples": list(base_config.false_positive_examples),
    }

    # Apply indicator_patterns overrides (merge)
    if "indicator_patterns" in overrides:
        for category, patterns in overrides["indicator_patterns"].items():
            if category in config_dict["indicator_patterns"]:
                config_dict["indicator_patterns"][category].extend(patterns)
            else:
                config_dict["indicator_patterns"][category] = patterns

    # Apply false_positive_rules overrides (append)
    if "false_positive_rules" in overrides:
        for rule_data in overrides["false_positive_rules"]:
            new_rule = FalsePositiveRule(
                pattern=rule_data["pattern"],
                reason=rule_data["reason"],
                auto_downgrade=rule_data.get("auto_downgrade", False),
                target_risk=rule_data.get("target_risk", "low"),
            )
            config_dict["false_positive_rules"].append(new_rule)

    # Apply prompt_role override (replace)
    if "prompt_role" in overrides:
        config_dict["prompt_role"] = overrides["prompt_role"]

    # Apply framework_knowledge override (append)
    if "framework_knowledge" in overrides:
        config_dict["framework_knowledge"] += "\n\n" + overrides["framework_knowledge"]

    # Apply display_name override
    if "display_name" in overrides:
        config_dict["display_name"] = overrides["display_name"]

    return FrameworkConfig(**config_dict)
