# Python Code Style Rules

## Overview
This document defines the coding standards and style requirements for Python projects. All code must adhere to these standards to ensure consistency, readability, and maintainability.

## PEP 8 Compliance

### Core Requirements
- **Mandatory**: Follow PEP 8 style guide strictly
- **Line Length**: Maximum 100 characters (aligned with Black formatter)
- **Indentation**: 4 spaces (no tabs)
- **Encoding**: UTF-8 for all Python files
- **Imports**: One import per line, grouped properly

### Line Length Examples
✅ **DO**: Keep lines under 100 characters
```python
def calculate_user_metrics(user_data: dict, include_historical: bool = True) -> UserMetrics:
    """Calculate comprehensive user metrics including engagement and activity."""
    return UserMetrics(user_data, include_historical)
```

❌ **DON'T**: Exceed 100 characters
```python
def calculate_user_metrics_with_historical_data_and_engagement_scores(user_data: dict, include_historical_data: bool = True) -> UserMetrics:
    return UserMetrics(user_data, include_historical_data)
```

## Black Formatter Configuration

### Setup Requirements
- **Formatter**: Black with 100-character line length
- **Configuration**: Add to `pyproject.toml`:

```toml
[tool.black]
line-length = 100
target-version = ['py311']
include = '\.pyi?$'
extend-exclude = '''
/(
  \.git
  | \.venv
  | build
  | dist
)/
'''
```

### Pre-commit Integration
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/psf/black
    rev: 23.12.1
    hooks:
      - id: black
        args: [--line-length=100]
```

## Ruff Linting Configuration

### Required Rules
Configure Ruff in `pyproject.toml` with comprehensive rule set:

```toml
[tool.ruff]
line-length = 100
target-version = "py311"
select = [
    "E",   # pycodestyle errors
    "W",   # pycodestyle warnings
    "F",   # pyflakes
    "I",   # isort
    "B",   # flake8-bugbear
    "C4",  # flake8-comprehensions
    "UP",  # pyupgrade
    "S",   # bandit (security)
    "N",   # pep8-naming
    "D",   # pydocstyle
    "PL",  # pylint
]
ignore = [
    "D100", # Missing docstring in public module
    "D104", # Missing docstring in public package
]
fixable = ["ALL"]
unfixable = []

[tool.ruff.pydocstyle]
convention = "google"

[tool.ruff.per-file-ignores]
"tests/**/*.py" = ["S101"]  # Allow assert in tests
```

### Security Rules (Bandit Integration)
- **S101**: No assert statements (except in tests)
- **S106**: No hardcoded passwords
- **S108**: Insecure temporary file usage
- **S301**: Pickle usage (security risk)

## Import Organization Standards

### Import Order (isort compatible)
1. **Standard library imports**
2. **Third-party imports**
3. **Local application imports**

✅ **DO**: Proper import organization
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

### Import Configuration
```toml
[tool.isort]
profile = "black"
line_length = 100
multi_line_output = 3
include_trailing_comma = true
force_grid_wrap = 0
use_parentheses = true
ensure_newline_before_comments = true
```

## Naming Conventions

### Variables and Functions
- **snake_case** for variables, functions, and modules

✅ **DO**: Use snake_case
```python
user_profile = get_user_profile()
max_retry_count = 3

def calculate_total_score(scores: list[int]) -> int:
    return sum(scores)
```

❌ **DON'T**: Use camelCase or other formats
```python
userProfile = getUserProfile()  # Wrong
maxRetryCount = 3              # Wrong

def calculateTotalScore(scores):  # Wrong
    return sum(scores)
```

### Classes
- **PascalCase** for class names

✅ **DO**: Use PascalCase for classes
```python
class UserProfile:
    def __init__(self, user_id: str):
        self.user_id = user_id

class DatabaseConnection:
    pass
```

### Constants
- **UPPER_CASE** with underscores for constants

✅ **DO**: Use UPPER_CASE for constants
```python
MAX_RETRY_ATTEMPTS = 5
DEFAULT_TIMEOUT_SECONDS = 30
API_BASE_URL = "https://api.example.com"
```

### Private Members
- **Single underscore** prefix for internal use
- **Double underscore** prefix for name mangling (rare cases)

✅ **DO**: Use underscore conventions properly
```python
class UserService:
    def __init__(self):
        self._connection = None  # Internal use
        self.__secret_key = None  # Name mangling (rare)

    def _validate_input(self, data: dict) -> bool:
        """Internal validation method."""
        return bool(data)
```

## Type Hints Requirements

### Mandatory Type Hints
- **All function signatures** must have type hints
- **Class attributes** should have type hints
- **Complex data structures** must be typed

✅ **DO**: Complete type annotations
```python
from typing import Optional, Union
from datetime import datetime

class User:
    id: str
    email: str
    created_at: datetime
    settings: Optional[dict] = None

def process_user_data(
    user_id: str,
    include_history: bool = True,
    max_records: Optional[int] = None
) -> dict[str, Union[str, int, list]]:
    """Process user data with proper type hints."""
    return {"user_id": user_id, "processed": True}
```

❌ **DON'T**: Missing or incomplete type hints
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

✅ **DO**: Use modern type syntax
```python
def process_items(items: list[str]) -> dict[str, int]:
    return {item: len(item) for item in items}

def get_value() -> str | None:
    return None
```

## Docstring Standards (Google Style)

### Function Docstrings
```python
def calculate_user_score(
    user_data: dict[str, any],
    weights: dict[str, float],
    normalize: bool = True
) -> float:
    """Calculate weighted user score based on multiple metrics.

    This function processes user data and applies configurable weights
    to calculate a composite score for ranking or evaluation purposes.

    Args:
        user_data: Dictionary containing user metrics and attributes.
            Expected keys: 'engagement', 'activity', 'retention'.
        weights: Weight coefficients for each metric. Keys should match
            those in user_data.
        normalize: Whether to normalize the final score to 0-1 range.

    Returns:
        Calculated weighted score as a float. Range depends on normalize
        parameter: [0.0, 1.0] if True, unbounded if False.

    Raises:
        ValueError: If user_data is empty or weights don't match metrics.
        KeyError: If required metrics are missing from user_data.

    Example:
        >>> data = {"engagement": 0.8, "activity": 0.6, "retention": 0.9}
        >>> weights = {"engagement": 0.4, "activity": 0.3, "retention": 0.3}
        >>> score = calculate_user_score(data, weights)
        >>> print(f"User score: {score:.2f}")
        User score: 0.77
    """
    if not user_data:
        raise ValueError("User data cannot be empty")

    # Implementation here
    return 0.77
```

### Class Docstrings
```python
class UserMetricsCalculator:
    """Calculate and manage user engagement metrics.

    This class provides methods to compute various user metrics including
    engagement scores, activity levels, and retention rates. It supports
    both real-time and batch processing of user data.

    Attributes:
        config: Configuration settings for metric calculations.
        cache_enabled: Whether to cache intermediate results for performance.

    Example:
        >>> calculator = UserMetricsCalculator(cache_enabled=True)
        >>> score = calculator.calculate_engagement(user_data)
        >>> print(f"Engagement: {score}")
    """

    def __init__(self, config: dict[str, any], cache_enabled: bool = False):
        """Initialize the metrics calculator.

        Args:
            config: Configuration dictionary with calculation parameters.
            cache_enabled: Enable caching for improved performance.
        """
        self.config = config
        self.cache_enabled = cache_enabled
```

## Code Complexity Limits

### Cognitive Complexity (SonarQube Standard)
- **Maximum cognitive complexity**: 15 per function/method
- **Recommended**: Keep under 10 for better maintainability

✅ **DO**: Simple, readable functions
```python
def process_user_registration(user_data: dict[str, str]) -> bool:
    """Process user registration with clear, simple logic."""
    if not user_data.get("email"):
        return False

    if not _is_valid_email(user_data["email"]):
        return False

    if _user_exists(user_data["email"]):
        return False

    return _create_user(user_data)

def _is_valid_email(email: str) -> bool:
    """Helper function to validate email format."""
    return "@" in email and "." in email
```

❌ **DON'T**: Complex nested logic
```python
def process_user_registration(user_data):
    """Overly complex function with high cognitive complexity."""
    if user_data and user_data.get("email"):
        if "@" in user_data["email"] and "." in user_data["email"]:
            if not any(u.email == user_data["email"] for u in existing_users):
                if user_data.get("age") and int(user_data["age"]) >= 18:
                    if user_data.get("country") in allowed_countries:
                        if user_data.get("terms_accepted") == "true":
                            # More nested conditions...
                            return create_user(user_data)
    return False
```

### Cyclomatic Complexity
- **Maximum**: 10 per function
- **Recommended**: Keep under 7

### Function Length
- **Maximum**: 50 lines per function
- **Recommended**: 20 lines or fewer

## Error Handling Standards

### Exception Specificity
✅ **DO**: Catch specific exceptions
```python
def load_config_file(file_path: str) -> dict[str, any]:
    """Load configuration from file with proper error handling."""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except FileNotFoundError:
        logger.error(f"Config file not found: {file_path}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in config file: {e}")
        raise
    except PermissionError:
        logger.error(f"Permission denied reading config: {file_path}")
        raise
```

❌ **DON'T**: Catch generic exceptions
```python
def load_config_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except:  # Too broad, hides errors
        return {}
```

## Code Organization

### Module Structure
```python
"""Module docstring describing purpose and usage.

This module provides utilities for user data processing and validation.
It includes functions for data transformation, validation, and persistence.

Example:
    >>> from src.utils.user_utils import validate_user_data
    >>> is_valid = validate_user_data(user_dict)
"""

# Standard library imports
import json
import logging
from datetime import datetime
from typing import Optional

# Third-party imports
import pydantic
from sqlalchemy import create_engine

# Local imports
from src.models.user import User
from src.config import settings

# Module-level constants
DEFAULT_BATCH_SIZE = 100
MAX_RETRY_ATTEMPTS = 3

# Logger setup
logger = logging.getLogger(__name__)

# Rest of module code...
```

### File Organization
- One class per file (generally)
- Related functions can be grouped in modules
- Use `__init__.py` for package initialization

## Performance Considerations

### List Comprehensions vs Loops
✅ **DO**: Use list comprehensions for simple transformations
```python
# Simple transformation
squared_numbers = [x**2 for x in numbers]

# With condition
even_squares = [x**2 for x in numbers if x % 2 == 0]
```

❌ **DON'T**: Use list comprehensions for complex logic
```python
# Too complex for comprehension
results = [
    complex_calculation(x) if validate(x) and check_condition(x)
    else default_value(x) if x > threshold
    else fallback_value
    for x in items
]

# Better as a regular loop with clear logic
results = []
for x in items:
    if validate(x) and check_condition(x):
        results.append(complex_calculation(x))
    elif x > threshold:
        results.append(default_value(x))
    else:
        results.append(fallback_value)
```

### String Formatting
✅ **DO**: Use f-strings for string formatting
```python
user_id = "123"
message = f"Processing user {user_id} at {datetime.now()}"

# For logging with lazy evaluation
logger.info("User %s processed successfully", user_id)
```

❌ **DON'T**: Use old-style formatting
```python
message = "Processing user %s at %s" % (user_id, datetime.now())
message = "Processing user {} at {}".format(user_id, datetime.now())
```

## Validation and Enforcement

### Pre-commit Hooks
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/psf/black
    rev: 23.12.1
    hooks:
      - id: black
        args: [--line-length=100]

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.1.9
    hooks:
      - id: ruff
        args: [--fix, --exit-non-zero-on-fix]

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.8.0
    hooks:
      - id: mypy
        additional_dependencies: [types-requests]
```

### CI/CD Integration
```yaml
# GitHub Actions example
- name: Code Quality Checks
  run: |
    black --check --line-length=100 src/
    ruff check src/
    mypy src/
```

## References
- [PEP 8 Style Guide](https://pep8.org/)
- [Black Code Formatter](https://black.readthedocs.io/)
- [Ruff Linter](https://docs.astral.sh/ruff/)
- [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)
- [SonarQube Cognitive Complexity](https://docs.sonarqube.org/latest/user-guide/metric-definitions/#complexity)
