# Safe Refactoring Workflow

## When to Use
Use this skill when improving code structure, readability, or maintainability without changing external behavior. Refactor to eliminate code smells, reduce complexity, or prepare code for new features.

## Prerequisites
- Comprehensive test suite with good coverage (≥80%)
- All tests passing before refactoring
- Version control with clean working directory
- Understanding of the code being refactored
- Clear refactoring goal

## Workflow Steps

### 1. Ensure Tests Exist and Pass
```bash
cd /path/to/project
source .venv/bin/activate

# Run full test suite
pytest tests/ -v

# Check coverage
pytest tests/ --cov=src --cov-report=term-missing --cov-fail-under=80
```

**Pre-Refactoring Checklist**:
- [ ] All tests pass
- [ ] Coverage ≥ 80%
- [ ] No pending changes in git
- [ ] Tests cover the code being refactored
- [ ] Tests are reliable (not flaky)

**If tests don't exist**:
```bash
# Write tests first using TDD workflow
# See tdd-workflow.md for guidance
```

### 2. Identify Code Smells
```bash
# Check code complexity
ruff check src/ --select C901  # McCabe complexity

# Check for code smells
ruff check src/ --select ALL

# Manual code smell identification
```

**Common Code Smells**:
- **Long Method**: Functions >50 lines
- **Large Class**: Classes with too many responsibilities
- **Long Parameter List**: Functions with >5 parameters
- **Duplicate Code**: Repeated code blocks
- **Dead Code**: Unused functions or variables
- **Magic Numbers**: Hardcoded values without explanation
- **Deep Nesting**: >4 levels of indentation
- **God Object**: Class that knows/does too much
- **Feature Envy**: Method uses another class more than its own
- **Data Clumps**: Same group of data items together

### 3. Choose Refactoring Pattern
Select appropriate refactoring technique based on the code smell:

**Extract Method**:
```python
# Before: Long method
def process_order(order):
    # Validate order (10 lines)
    if not order.items:
        raise ValueError("Empty order")
    # ... more validation

    # Calculate total (15 lines)
    total = 0
    for item in order.items:
        total += item.price * item.quantity
    # ... more calculation

    # Apply discount (10 lines)
    if order.customer.is_premium:
        total *= 0.9
    # ... more discount logic

    return total

# After: Extracted methods
def process_order(order):
    validate_order(order)
    total = calculate_total(order)
    total = apply_discount(total, order.customer)
    return total

def validate_order(order):
    if not order.items:
        raise ValueError("Empty order")
    # ... validation logic

def calculate_total(order):
    return sum(item.price * item.quantity for item in order.items)

def apply_discount(total, customer):
    if customer.is_premium:
        return total * 0.9
    return total
```

**Extract Class**:
```python
# Before: God object
class User:
    def __init__(self, name, email, street, city, zip_code):
        self.name = name
        self.email = email
        self.street = street
        self.city = city
        self.zip_code = zip_code

    def get_full_address(self):
        return f"{self.street}, {self.city} {self.zip_code}"

# After: Extracted Address class
class Address:
    def __init__(self, street, city, zip_code):
        self.street = street
        self.city = city
        self.zip_code = zip_code

    def get_full_address(self):
        return f"{self.street}, {self.city} {self.zip_code}"

class User:
    def __init__(self, name, email, address):
        self.name = name
        self.email = email
        self.address = address
```

**Replace Magic Numbers with Constants**:
```python
# Before: Magic numbers
def calculate_discount(price):
    if price > 100:
        return price * 0.9
    return price

# After: Named constants
DISCOUNT_THRESHOLD = 100
DISCOUNT_RATE = 0.9

def calculate_discount(price):
    if price > DISCOUNT_THRESHOLD:
        return price * DISCOUNT_RATE
    return price
```

**Simplify Conditional**:
```python
# Before: Complex conditional
def get_shipping_cost(order):
    if order.total > 100 and order.customer.is_premium and order.destination == "domestic":
        return 0
    elif order.total > 50 and order.destination == "domestic":
        return 5
    else:
        return 10

# After: Guard clauses and extracted methods
def get_shipping_cost(order):
    if is_free_shipping(order):
        return 0
    if is_discounted_shipping(order):
        return 5
    return 10

def is_free_shipping(order):
    return (order.total > 100 and
            order.customer.is_premium and
            order.destination == "domestic")

def is_discounted_shipping(order):
    return order.total > 50 and order.destination == "domestic"
```

### 4. Make Small, Incremental Changes
```bash
# Refactor in small steps
# After each change:

# 1. Run tests
pytest tests/ -v

# 2. Commit if tests pass
git add .
git commit -m "refactor: extract calculate_total method"

# 3. Continue to next refactoring
```

**Refactoring Workflow**:
1. Make one small change
2. Run tests
3. If tests pass → commit
4. If tests fail → revert and try again
5. Repeat

### 5. Run Tests After Each Change
```bash
# Quick test run for affected module
pytest tests/test_module.py -v

# Full test suite periodically
pytest tests/ -v

# With coverage to ensure no regression
pytest tests/ --cov=src --cov-report=term-missing
```

**Test Failure Response**:
```bash
# If tests fail, revert immediately
git diff  # Review changes
git checkout -- .  # Revert changes

# Or use git stash
git stash  # Save changes
# Fix the issue
git stash pop  # Reapply changes
```

### 6. Update Documentation
```bash
# Update docstrings for refactored functions
# Update inline comments if logic changed
# Update README if public API changed
```

**Documentation Updates**:
```python
# Before refactoring
def process(data):
    """Process data."""
    # Implementation

# After refactoring - update docstring
def process(data):
    """Process data by validating, transforming, and storing.

    Args:
        data: Dictionary containing raw input data

    Returns:
        ProcessedData object with validation results

    Raises:
        ValueError: If data validation fails

    Example:
        >>> result = process({"key": "value"})
        >>> print(result.status)
        'success'
    """
    validate_data(data)
    transformed = transform_data(data)
    return store_data(transformed)
```

### 7. Check Code Quality Metrics
```bash
# Check complexity after refactoring
ruff check src/ --select C901

# Run full linting
ruff check src/

# Type checking
mypy src/

# Format code
black src/
isort src/
```

**Quality Improvement Checklist**:
- [ ] Cognitive complexity reduced
- [ ] Function length reduced
- [ ] Duplicate code eliminated
- [ ] Magic numbers replaced with constants
- [ ] Deep nesting reduced
- [ ] Parameter count reduced
- [ ] Type hints added/improved
- [ ] Documentation updated

### 8. Verify No Regression
```bash
# Run comprehensive test suite
pytest tests/ -v --cov=src --cov-report=html

# Check coverage hasn't decreased
pytest tests/ --cov=src --cov-fail-under=80

# Run integration tests if available
pytest tests/integration/ -v

# Performance check (if applicable)
python -m cProfile -o profile.stats src/main.py
```

### 9. Review Changes
```bash
# Review all changes made
git diff main...HEAD

# Check changed files
git diff --name-only main...HEAD

# Review specific file
git diff main...HEAD src/module.py
```

**Self-Review Checklist**:
- [ ] Code is more readable
- [ ] Code is more maintainable
- [ ] No behavior changes
- [ ] All tests pass
- [ ] Coverage maintained or improved
- [ ] Documentation updated
- [ ] No new complexity introduced
- [ ] Follows project conventions

### 10. Create Refactoring Summary
```bash
# Document refactoring changes
cat > refactoring-summary.md << 'EOF'
# Refactoring Summary
**Date**: $(date +%Y-%m-%d)
**Developer**: $(git config user.name)

## Objective
<!-- What was the goal of this refactoring? -->

## Changes Made
<!-- List of refactoring patterns applied -->
1. Extracted method: calculate_total()
2. Simplified conditional in process_order()
3. Replaced magic numbers with constants

## Code Smells Addressed
- Long Method in process_order()
- Magic numbers in discount calculation
- Complex conditional in shipping logic

## Metrics

### Before Refactoring
- Cognitive Complexity: 25
- Function Length: 80 lines
- Test Coverage: 82%

### After Refactoring
- Cognitive Complexity: 8
- Function Length: 15 lines
- Test Coverage: 85%

## Test Results
- All tests passing: ✅
- Coverage maintained: ✅
- No regressions: ✅

## Files Changed
- src/orders/processor.py
- tests/test_processor.py

## Next Steps
<!-- Any follow-up refactoring needed -->
EOF
```

## Success Criteria
- ✅ All tests pass
- ✅ Code coverage maintained or improved
- ✅ Code complexity reduced
- ✅ Code readability improved
- ✅ No behavior changes
- ✅ Documentation updated
- ✅ Changes committed incrementally
- ✅ No regressions introduced

## Common Issues

### Issue: Tests fail after refactoring
**Solution**:
```bash
# Revert immediately
git checkout -- .

# Analyze why tests failed
pytest tests/ -v --tb=short

# Make smaller changes
# Refactor one thing at a time
```

### Issue: Coverage decreased
**Solution**:
```bash
# Identify uncovered lines
pytest tests/ --cov=src --cov-report=term-missing

# Add tests for new extracted methods
# Ensure all code paths are tested
```

### Issue: Refactoring introduces bugs
**Solution**:
- Make smaller changes
- Run tests more frequently
- Use IDE refactoring tools (safer)
- Add more tests before refactoring
- Pair program during complex refactoring

### Issue: Don't know where to start
**Solution**:
1. Start with easiest code smells (magic numbers)
2. Use automated tools to identify issues
3. Focus on most frequently changed code
4. Refactor code you're currently working on
5. Follow the Boy Scout Rule (leave code better than you found it)

## Examples

### Example 1: Extract Method Refactoring
```python
# Before: Long method with multiple responsibilities
def generate_report(data):
    # Validate data
    if not data:
        raise ValueError("No data")
    if not isinstance(data, list):
        raise TypeError("Data must be list")

    # Process data
    processed = []
    for item in data:
        if item.get('active'):
            processed.append({
                'name': item['name'],
                'value': item['value'] * 1.1
            })

    # Format output
    output = []
    for item in processed:
        output.append(f"{item['name']}: {item['value']:.2f}")

    return '\n'.join(output)

# After: Extracted methods
def generate_report(data):
    validate_data(data)
    processed = process_data(data)
    return format_output(processed)

def validate_data(data):
    if not data:
        raise ValueError("No data")
    if not isinstance(data, list):
        raise TypeError("Data must be list")

def process_data(data):
    return [
        {'name': item['name'], 'value': item['value'] * 1.1}
        for item in data
        if item.get('active')
    ]

def format_output(processed):
    return '\n'.join(
        f"{item['name']}: {item['value']:.2f}"
        for item in processed
    )
```

### Example 2: Replace Conditional with Polymorphism
```python
# Before: Type checking with conditionals
def calculate_area(shape):
    if shape.type == 'circle':
        return 3.14 * shape.radius ** 2
    elif shape.type == 'rectangle':
        return shape.width * shape.height
    elif shape.type == 'triangle':
        return 0.5 * shape.base * shape.height
    else:
        raise ValueError("Unknown shape")

# After: Polymorphism
from abc import ABC, abstractmethod

class Shape(ABC):
    @abstractmethod
    def calculate_area(self):
        pass

class Circle(Shape):
    def __init__(self, radius):
        self.radius = radius

    def calculate_area(self):
        return 3.14 * self.radius ** 2

class Rectangle(Shape):
    def __init__(self, width, height):
        self.width = width
        self.height = height

    def calculate_area(self):
        return self.width * self.height

class Triangle(Shape):
    def __init__(self, base, height):
        self.base = base
        self.height = height

    def calculate_area(self):
        return 0.5 * self.base * self.height
```

### Example 3: Introduce Parameter Object
```python
# Before: Long parameter list
def create_user(name, email, street, city, state, zip_code, phone, country):
    user = User(name, email)
    user.address = Address(street, city, state, zip_code, country)
    user.phone = phone
    return user

# After: Parameter object
from dataclasses import dataclass

@dataclass
class UserData:
    name: str
    email: str
    address: 'AddressData'
    phone: str

@dataclass
class AddressData:
    street: str
    city: str
    state: str
    zip_code: str
    country: str

def create_user(user_data: UserData):
    user = User(user_data.name, user_data.email)
    user.address = Address(**user_data.address.__dict__)
    user.phone = user_data.phone
    return user
```

## Related Skills
- [`tdd-workflow.md`](./tdd-workflow.md) - Ensure tests before refactoring
- [`code-review-workflow.md`](./code-review-workflow.md) - Review refactored code
- [`performance-analysis.md`](./performance-analysis.md) - Optimize during refactoring

## Best Practices
- Always have tests before refactoring
- Make small, incremental changes
- Run tests after each change
- Commit frequently
- Use IDE refactoring tools when available
- Don't refactor and add features simultaneously
- Focus on one code smell at a time
- Keep refactoring sessions short (< 2 hours)
- Pair program for complex refactoring
- Document why, not just what
- Follow the Boy Scout Rule
- Refactor when you touch code, not separately
- Use automated refactoring tools
- Review refactoring patterns regularly
- Don't over-engineer
