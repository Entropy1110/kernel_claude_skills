# Mali Surface Mapping

Build codebase index and identify analysis candidates.

## Description

Performs initial surface mapping:
1. **build_ts_index**: Generate tree-sitter AST tags
2. **map_surface**: Scan for framework entrypoints
3. **select_candidates**: Score and rank candidates
4. **enrich_candidates**: Add context for analysis

This is the first skill in a step-by-step workflow.

## Usage

```
/mali-map --repo=/path/to/repo --scope=drivers/gpu/drm/panthor --framework=drm --session-id=my-analysis
```

### Examples

Start new DRM analysis:
```
/mali-map --repo=/path/to/linux --scope=drivers/gpu/drm/panthor --framework=drm --session-id=panthor-001
```

Map application code:
```
/mali-map --repo=/path/to/app --scope=src --framework=application --session-id=app-001
```

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `--repo` | Yes | - | Path to repository |
| `--scope` | Yes | - | Directory to analyze |
| `--framework` | No | `drm` | Framework type |
| `--session-id` | Yes | - | Session ID for tracking |

## Output

Creates session with:
- **tags**: Tree-sitter AST tags for all files
- **candidates**: Scored and ranked analysis targets
- **entrypoints**: Detected framework entry points

## Next Steps

After mapping, continue with:
```
/mali-triage --session-id=<session>
```
