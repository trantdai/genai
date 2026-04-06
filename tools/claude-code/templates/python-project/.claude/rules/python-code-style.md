# Python Code Style Rules

## Overview
Coding standards and style requirements ensuring consistency, readability, and maintainability.

## Core Requirements
- **PEP 8 Compliance**: Follow PEP 8 style guide strictly
- **Line Length**: Maximum 100 characters (Black formatter default)
- **Indentation**: 4 spaces (no tabs)
- **Encoding**: UTF-8 for all Python files

## Formatting Tools

### Black Formatter
- **Line length**: 100 characters
- **Configuration**: Add to `pyproject.toml` ([Black docs](https://black.readthedocs.io/))

### Ruff Linter
- **Rules**: Comprehensive rule set including security checks
- **Configuration**: See [Ruff documentation](https://docs.astral.sh/ruff/)
- **Key rule sets**: pycodestyle, pyflakes, isort, flake8-bugbear, bandit

## Import Organization

### Import Order (isort compatible)
1. Standard library imports
2. Third-party imports
3. Local application imports

✅ **DO**: Proper organization
```python
# Standard library
import os
from datetime import datetime
from typing import Optional

# Third-party
import pydantic
from fastapi import FastAPI

# Local
from src.models import User
from src.utils import validate_email
```

## Naming Conventions

### Variables and Functions
- **snake_case** for variables, functions, modules

✅ **DO**:
```python
user_profile = get_user_profile()
max_retry_count = 3

def calculate_total_score(scores: list[int]) -> int:
    return sum(scores)
```

❌ **DON'T**:
```python
userProfile = getUserProfile()  # camelCase
MaxRetryCount = 3              # PascalCase
```

### Classes
- **PascalCase** for class names

✅ **DO**:
```python
class UserProfile:
    pass

class DatabaseConnection:
    pass
```

### Constants
- **UPPER_CASE** with underscores

✅ **DO**:
```python
MAX_RETRY_ATTEMPTS = 5
DEFAULT_TIMEOUT_SECONDS = 30
API_BASE_URL = "https://api.example.com"
```

### Private Members
- **Single underscore** prefix for internal use
- **Double underscore** prefix for name mangling (rare)

✅ **DO**:
```python
class UserService:
    def __init__(self):
        self._connection = None  # Internal use
        self.__secret_key = None  # Name mangling (rare)
```

## Type Hints Requirements

### Mandatory Type Hints
- **All function signatures** must have type hints
- **Class attributes** should have type hints
- **Complex data structures** must be typed

✅ **DO**: Complete type annotations
```python
from typing import Optional

class User:
    id: str
    email: str
    settings: Optional[dict] = None

def process_user_data(
    user_id: str,
    include_history: bool = True,
    max_records: Optional[int] = None
) -> dict[str, str | int | list]:
    """Process user data with proper type hints."""
    return {"user_id": user_id, "processed": True}
```

❌ **DON'T**: Missing type hints
```python
def process_user_data(user_id, include_history=True):  # No types
    return {"user_id": user_id}

def get_user(user_id: str):  # Missing return type
    return User(user_id)
```

### Modern Type Syntax (Python 3.11+)
- Use `list[str]` instead of `List[str]`
- Use `dict[str, int]` instead of `Dict[str, int]`
- Use `X | Y` instead of `Union[X, Y]`

## Docstring Standards (Google Style)

### Function Docstrings
```python
def calculate_user_score(
    user_data: dict[str, any],
    weights: dict[str, float],
    normalize: bool = True
) -> float:
    """Calculate weighted user score based on multiple metrics.

    Args:
        user_data: Dictionary containing user metrics (engagement, activity, retention).
        weights: Weight coefficients for each metric.
        normalize: Whether to normalize score to 0-1 range.

    Returns:
        Calculated weighted score as float. Range: [0.0, 1.0] if normalized.

    Raises:
        ValueError: If user_data is empty or weights don't match metrics.
        KeyError: If required metrics missing from user_data.

    Example:
        >>> data = {"engagement": 0.8, "activity": 0.6}
        >>> weights = {"engagement": 0.6, "activity": 0.4}
        >>> score = calculate_user_score(data, weights)
    """
    pass
```

### Class Docstrings
```python
class UserMetricsCalculator:
    """Calculate and manage user engagement metrics.

    This class provides methods to compute user metrics including
    engagement scores, activity levels, and retention rates.

    Attributes:
        config: Configuration settings for calculations.
        cache_enabled: Whether to cache intermediate results.

    Example:
        >>> calculator = UserMetricsCalculator(cache_enabled=True)
        >>> score = calculator.calculate_engagement(user_data)
    """
    pass
```

## Code Complexity Limits

### Cognitive Complexity
- **Maximum**: 15 per function/method
- **Recommended**: Keep under 10

✅ **DO**: Simple, readable functions
```python
def process_user_registration(user_data: dict[str, str]) -> bool:
    """Process user registration with clear logic."""
    if not user_data.get("email"):
        return False
    
    if not _is_valid_email(user_data["email"]):
        return False
    
    if _user_exists(user_data["email"]):
        return False
    
    return _create_user(user_data)
```

❌ **DON'T**: Complex nested logic
```python
def process_user_registration(user_data):
    if user_data and user_data.get("email"):
        if "@" in user_data["email"] and "." in user_data["email"]:
            if not any(u.email == user_data["email"] for u in existing_users):
                if user_data.get("age") and int(user_data["age"]) >= 18:
                    # More nesting...
                    pass
```

### Other Limits
- **Cyclomatic Complexity**: Maximum 10 per function
- **Function Length**: Maximum 50 lines (recommended 20 or fewer)
- **Parameters**: Maximum 5 per function

## Error Handling Standards

✅ **DO**: Catch specific exceptions
```python
def load_config_file(file_path: str) -> dict[str, any]:
    """Load configuration with proper error handling."""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except FileNotFoundError:
        logger.error(f"Config file not found: {file_path}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON: {e}")
        raise
```

❌ **DON'T**: Catch generic exceptions
```python
def load_config_file(file_path):
    try:
        return json.load(open(file_path))
    except:  # Too broad
        return {}
```

## Performance Considerations

### List Comprehensions
✅ **DO**: Use for simple transformations
```python
squared_numbers = [x**2 for x in numbers]
even_squares = [x**2 for x in numbers if x % 2 == 0]
```

❌ **DON'T**: Use for complex logic
```python
# Too complex - use regular loop
results = [
    complex_calculation(x) if validate(x) and check(x)
    else default_value(x) if x > threshold
    else fallback_value
    for x in items
]
```

### String Formatting
✅ **DO**: Use f-strings
```python
user_id = "123"
message = f"Processing user {user_id} at {datetime.now()}"
```

❌ **DON'T**: Use old-style formatting
```python
message = "Processing user %s" % user_id
message = "Processing user {}".format(user_id)
```

## Validation and Enforcement

### Pre-commit Hooks
Configure in `.pre-commit-config.yaml` ([pre-commit docs](https://pre-commit.com/))

### CI/CD Integration
```yaml
# GitHub Actions example
- name: Code Quality Checks
  run: |
    black --check --line-length=100 src/
    ruff check src/
    mypy src/
```

## Key Principles

- **Readability counts** - Code is read more than written
- **Explicit is better than implicit** - Clear over clever
- **Simple is better than complex** - Avoid over-engineering
- **Consistency** - Follow project conventions
- **Type safety** - Use type hints everywhere

## References
- [PEP 8 Style Guide](https://pep8.org/)
- [Black Code Formatter](https://black.readthedocs.io/)
- [Ruff Linter](https://docs.astral.sh/ruff/)
- [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)
- [SonarQube Cognitive Complexity](https://docs.sonarqube.org/latest/user-guide/metric-definitions/#complexity)
