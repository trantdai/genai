# Python Code Style Rules

## Core Requirements
- **PEP 8**: Follow strictly
- **Line Length**: 100 characters max
- **Indentation**: 4 spaces (no tabs)
- **Encoding**: UTF-8

## Formatters
- **black**: 100 char lines
- **ruff**: Linting (pycodestyle, pyflakes, isort, flake8-bugbear, bandit)

## Import Organization

1. Standard library
2. Third-party
3. Local application

```python
import os
from datetime import datetime

import requests

from src.models import User
```

## Naming Conventions

- **Variables/Functions**: `snake_case`
- **Classes**: `PascalCase`
- **Constants**: `UPPER_CASE`
- **Private**: `_single_underscore`

## Type Hints (Mandatory)

All functions must have type hints:

```python
class User:
    id: str
    email: str
    settings: Optional[dict] = None

def process_data(
    user_id: str,
    include_history: bool = True,
    max_records: Optional[int] = None
) -> dict[str, str | int]:
    return {"user_id": user_id, "processed": True}
```

**Modern Syntax (Python 3.13+)**:
- `list[str]` not `List[str]`
- `dict[str, int]` not `Dict[str, int]`
- `X | Y` not `Union[X, Y]`

## Docstrings (Google Style)

```python
def calculate_score(
    user_data: dict[str, any],
    weights: dict[str, float],
    normalize: bool = True
) -> float:
    """Calculate weighted user score.

    Args:
        user_data: User metrics (engagement, activity, retention).
        weights: Weight coefficients for each metric.
        normalize: Whether to normalize to 0-1 range.

    Returns:
        Weighted score. Range: [0.0, 1.0] if normalized.

    Raises:
        ValueError: If user_data empty or weights mismatch.
    """
    pass
```

## Complexity Limits

- **Cognitive Complexity**: ≤15 per function (recommended ≤10)
- **Cyclomatic Complexity**: ≤10 per function
- **Function Length**: ≤50 lines (recommended ≤20)
- **Parameters**: ≤5 per function

## Error Handling

✅ **DO**: Catch specific exceptions
```python
def load_config(file_path: str) -> dict:
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error(f"Config not found: {file_path}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON: {e}")
        raise
```

❌ **DON'T**: Catch generic exceptions

## Performance

✅ **DO**:
- List comprehensions for simple transformations
- f-strings for formatting

❌ **DON'T**:
- Old-style formatting (`%s`, `.format()`)

## Key Principles

- **Readability counts** - Code is read more than written
- **Explicit > implicit** - Clear over clever
- **Simple > complex** - Avoid over-engineering
- **Consistency** - Follow project conventions
- **Type safety** - Use type hints everywhere
