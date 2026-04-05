# Python Performance Standards

## Overview

Performance optimization in Python requires understanding the language's characteristics, choosing appropriate data structures, and using profiling tools to identify bottlenecks. This guide provides actionable patterns for writing high-performance Python code while maintaining readability and maintainability.

### Key Performance Principles

1. **Measure First**: Always profile before optimizing
2. **Algorithmic Efficiency**: Choose the right algorithm and data structures
3. **Memory Awareness**: Understand memory usage patterns
4. **I/O Optimization**: Minimize blocking operations
5. **Concurrency**: Use appropriate parallelization strategies
6. **Caching**: Implement smart caching strategies
7. **Native Extensions**: Leverage compiled libraries when needed

### Performance Mindset

- **Premature optimization is the root of all evil** - Donald Knuth
- Focus on hot paths and bottlenecks identified through profiling
- Optimize for the common case, handle edge cases gracefully
- Balance performance with code maintainability
- Consider total cost of ownership, not just execution speed

## Part 1: Overview and Code Optimization

### Algorithm and Data Structure Selection

✅ **DO**: Choose the right data structure for your use case

```python
import collections
import bisect
from typing import Dict, List, Set, Deque

# ✅ Use appropriate data structures
def efficient_data_structures():
    """Examples of efficient data structure usage."""

    # Use sets for membership testing (O(1) vs O(n) for lists)
    valid_ids = {1, 2, 3, 4, 5}  # O(1) lookup
    if user_id in valid_ids:  # Fast membership test
        process_user(user_id)

    # Use collections.deque for frequent insertions/deletions at both ends
    task_queue: Deque[str] = collections.deque()
    task_queue.append("new_task")  # O(1)
    task_queue.appendleft("priority_task")  # O(1)
    current_task = task_queue.popleft()  # O(1)

    # Use collections.Counter for counting operations
    word_counts = collections.Counter()
    for word in text.split():
        word_counts[word] += 1  # Efficient counting

    # Use collections.defaultdict to avoid key existence checks
    grouped_data = collections.defaultdict(list)
    for item in items:
        grouped_data[item.category].append(item)  # No KeyError handling needed

    # Use bisect for sorted list operations
    sorted_list = [1, 3, 5, 7, 9]
    insertion_point = bisect.bisect_left(sorted_list, 6)  # O(log n)
    bisect.insort(sorted_list, 6)  # O(n) but maintains sort order

# ✅ Efficient algorithms
def efficient_algorithms():
    """Use efficient algorithmic approaches."""

    # Use set operations for list comparisons
    def find_common_items_efficient(list1: List[int], list2: List[int]) -> Set[int]:
        return set(list1) & set(list2)  # O(n + m) instead of O(n * m)

    # Use dict.get() with default instead of checking existence
    def count_items_efficient(items: List[str]) -> Dict[str, int]:
        counts = {}
        for item in items:
            counts[item] = counts.get(item, 0) + 1  # Efficient counting
        return counts

    # Use list comprehensions for simple transformations
    def process_numbers_efficient(numbers: List[int]) -> List[int]:
        return [n * 2 for n in numbers if n > 0]  # Faster than loops

    # Use enumerate instead of range(len())
    def process_with_index_efficient(items: List[str]) -> List[tuple[int, str]]:
        return [(i, item.upper()) for i, item in enumerate(items)]

# ✅ String operations optimization
def efficient_string_operations():
    """Optimize string operations."""

    # Use join() for string concatenation
    def build_message_efficient(parts: List[str]) -> str:
        return " ".join(parts)  # O(n) instead of O(n²)

    # Use f-strings for formatting (Python 3.6+)
    def format_message_efficient(name: str, count: int) -> str:
        return f"User {name} has {count} items"  # Fastest string formatting

    # Use startswith/endswith for prefix/suffix checks
    def filter_files_efficient(filenames: List[str]) -> List[str]:
        return [f for f in filenames if f.endswith(('.py', '.pyx'))]

    # Use str methods for simple operations
    def clean_text_efficient(text: str) -> str:
        return text.strip().lower().replace('_', '-')
```

❌ **DON'T**: Use inefficient patterns

```python
# ❌ Inefficient data structure choices
def inefficient_patterns():
    """Examples of what to avoid."""

    # Don't use lists for membership testing
    valid_ids = [1, 2, 3, 4, 5]  # O(n) lookup
    if user_id in valid_ids:  # Slow for large lists
        process_user(user_id)

    # Don't use string concatenation in loops
    message = ""
    for part in parts:
        message += part + " "  # O(n²) - creates new string each time

    # Don't use nested loops when set operations work
    def find_common_items_slow(list1: List[int], list2: List[int]) -> List[int]:
        common = []
        for item1 in list1:  # O(n * m)
            for item2 in list2:
                if item1 == item2:
                    common.append(item1)
        return common

    # Don't repeatedly check dict keys
    def count_items_slow(items: List[str]) -> Dict[str, int]:
        counts = {}
        for item in items:
            if item in counts:  # Redundant check
                counts[item] += 1
            else:
                counts[item] = 1
        return counts
```

### Function and Loop Optimization

✅ **DO**: Optimize function calls and loops

```python
import functools
import operator
from typing import Any, Callable, List
import math

# ✅ Use built-in functions and operations
def efficient_operations():
    """Use optimized built-in operations."""

    # Use built-in functions (implemented in C)
    numbers = [1, 2, 3, 4, 5]

    total = sum(numbers)  # Faster than manual loop
    maximum = max(numbers)  # Faster than manual comparison
    minimum = min(numbers)  # Faster than manual comparison

    # Use operator module for simple operations
    from functools import reduce
    product = reduce(operator.mul, numbers, 1)  # Efficient multiplication

    # Use map() for simple transformations on large datasets
    squared = list(map(lambda x: x**2, numbers))  # Can be faster than comprehension

    # Use filter() for simple filtering
    evens = list(filter(lambda x: x % 2 == 0, numbers))

# ✅ Function call optimization
def optimize_function_calls():
    """Optimize expensive function calls."""

    # Cache expensive computations
    @functools.lru_cache(maxsize=128)
    def expensive_calculation(n: int) -> float:
        """Cache results of expensive calculations."""
        if n < 2:
            return 1
        return expensive_calculation(n-1) + expensive_calculation(n-2)

    # Avoid repeated attribute lookups in loops
    def process_items_efficiently(items: List[Any]):
        """Avoid repeated attribute access."""
        append = result.append  # Cache method reference
        upper = str.upper  # Cache method reference

        result = []
        for item in items:
            if hasattr(item, 'name'):
                append(upper(item.name))  # Use cached reference
        return result

    # Use local variables for frequently accessed globals
    def math_operations_efficient(values: List[float]) -> List[float]:
        """Cache global references as locals."""
        sqrt = math.sqrt  # Local reference is faster
        return [sqrt(v) for v in values if v > 0]

# ✅ Loop optimization techniques
def optimize_loops():
    """Optimize loop performance."""

    # Use list comprehensions for simple operations
    def square_positive_numbers(numbers: List[int]) -> List[int]:
        return [n**2 for n in numbers if n > 0]  # Faster than explicit loop

    # Use generator expressions for memory efficiency
    def sum_squares_memory_efficient(numbers: List[int]) -> int:
        return sum(n**2 for n in numbers if n > 0)  # Memory efficient

    # Pre-allocate lists when size is known
    def create_matrix_efficient(rows: int, cols: int) -> List[List[int]]:
        # Pre-allocate instead of growing dynamically
        return [[0] * cols for _ in range(rows)]

    # Use enumerate instead of manual indexing
    def process_with_indices(items: List[str]) -> List[str]:
        return [f"{i}: {item}" for i, item in enumerate(items)]

    # Use zip for parallel iteration
    def combine_lists_efficient(names: List[str], ages: List[int]) -> List[str]:
        return [f"{name} is {age}" for name, age in zip(names, ages)]

# ✅ Conditional optimization
def optimize_conditionals():
    """Optimize conditional logic."""

    # Use short-circuit evaluation
    def safe_divide(a: float, b: float) -> float:
        return a / b if b != 0 and a != 0 else 0.0  # Short-circuit on first False

    # Use dict lookup for multiple conditions
    def get_processing_function(operation: str) -> Callable:
        """Use dict instead of if/elif chain."""
        operations = {
            'add': operator.add,
            'subtract': operator.sub,
            'multiply': operator.mul,
            'divide': operator.truediv,
        }
        return operations.get(operation, lambda x, y: None)

    # Use sets for multiple equality checks
    def is_valid_status(status: str) -> bool:
        return status in {'active', 'pending', 'approved'}  # Faster than multiple ==
```

### Import and Module Optimization

✅ **DO**: Optimize imports and module usage

```python
# ✅ Efficient import strategies
# Import only what you need
from collections import defaultdict, Counter  # Specific imports
from typing import Dict, List, Optional  # Type hints don't affect runtime

# Use local imports for rarely used modules
def process_json_data(data: str):
    """Import json locally if rarely used."""
    import json  # Local import reduces startup time
    return json.loads(data)

# Cache expensive imports
class DataProcessor:
    def __init__(self):
        self._pandas = None
        self._numpy = None

    @property
    def pd(self):
        """Lazy import pandas."""
        if self._pandas is None:
            import pandas as pd
            self._pandas = pd
        return self._pandas

    @property
    def np(self):
        """Lazy import numpy."""
        if self._numpy is None:
            import numpy as np
            self._numpy = np
        return self._numpy

# ✅ Module-level optimizations
def module_optimization_patterns():
    """Patterns for module-level performance."""

    # Pre-compile regular expressions at module level
    import re

    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    PHONE_PATTERN = re.compile(r'^\+?1?[-.\s]?\(?(\d{3})\)?[-.\s]?(\d{3})[-.\s]?(\d{4})$')

    def validate_email(email: str) -> bool:
        """Use pre-compiled regex."""
        return EMAIL_PATTERN.match(email) is not None

    # Create constants at module level
    SECONDS_PER_DAY = 24 * 60 * 60
    BYTES_PER_MB = 1024 * 1024

    # Pre-calculate frequently used values
    FIBONACCI_CACHE = {0: 0, 1: 1}
    for i in range(2, 100):
        FIBONACCI_CACHE[i] = FIBONACCI_CACHE[i-1] + FIBONACCI_CACHE[i-2]
```

❌ **DON'T**: Use inefficient import patterns

```python
# ❌ Inefficient import patterns
import * from module  # Imports everything, slower startup

# Don't import inside hot loops
def process_many_items(items: List[str]):
    results = []
    for item in items:
        import json  # Don't do this - imports on every iteration
        results.append(json.loads(item))
    return results

# Don't use complex imports without caching
def get_data():
    from some.deeply.nested.module import expensive_function  # Repeated import cost
    return expensive_function()
```

### Class and Object Optimization

✅ **DO**: Optimize class and object usage

```python
from typing import Dict, List, NamedTuple, Optional
import dataclasses
from collections import namedtuple

# ✅ Use __slots__ for memory efficiency
class EfficientPoint:
    """Memory-efficient class with __slots__."""
    __slots__ = ['x', 'y', 'z']

    def __init__(self, x: float, y: float, z: float = 0.0):
        self.x = x
        self.y = y
        self.z = z

    def distance_from_origin(self) -> float:
        return (self.x**2 + self.y**2 + self.z**2)**0.5

# ✅ Use dataclasses for simple data containers
@dataclasses.dataclass(frozen=True, slots=True)  # Python 3.10+
class User:
    """Efficient data container."""
    id: int
    name: str
    email: str
    age: Optional[int] = None

# ✅ Use NamedTuple for immutable data
class Coordinate(NamedTuple):
    """Memory-efficient immutable coordinate."""
    x: float
    y: float
    z: float = 0.0

    def distance_from_origin(self) -> float:
        return (self.x**2 + self.y**2 + self.z**2)**0.5

# ✅ Property caching for expensive computations
class OptimizedCircle:
    """Circle with cached expensive properties."""

    def __init__(self, radius: float):
        self.radius = radius
        self._area = None
        self._circumference = None

    @property
    def area(self) -> float:
        """Cached area calculation."""
        if self._area is None:
            self._area = 3.14159 * self.radius ** 2
        return self._area

    @property
    def circumference(self) -> float:
        """Cached circumference calculation."""
        if self._circumference is None:
            self._circumference = 2 * 3.14159 * self.radius
        return self._circumference

    def update_radius(self, new_radius: float):
        """Update radius and clear cache."""
        self.radius = new_radius
        self._area = None
        self._circumference = None

# ✅ Use classmethod and staticmethod appropriately
class MathUtils:
    """Utility class with optimized methods."""

    @staticmethod
    def add(a: float, b: float) -> float:
        """Static method - no instance needed."""
        return a + b

    @classmethod
    def create_zero_point(cls) -> 'EfficientPoint':
        """Class method for alternative constructor."""
        return cls(0.0, 0.0, 0.0)

# ✅ Efficient factory patterns
class ObjectFactory:
    """Efficient object creation patterns."""

    def __init__(self):
        self._user_cache: Dict[int, User] = {}

    def get_user(self, user_id: int, name: str, email: str) -> User:
        """Cache expensive object creation."""
        if user_id not in self._user_cache:
            self._user_cache[user_id] = User(user_id, name, email)
        return self._user_cache[user_id]

    def create_users_batch(self, user_data: List[Dict[str, any]]) -> List[User]:
        """Efficient batch creation."""
        return [
            User(
                id=data['id'],
                name=data['name'],
                email=data['email'],
                age=data.get('age')
            )
            for data in user_data
        ]
```

❌ **DON'T**: Use inefficient class patterns

```python
# ❌ Inefficient class patterns
class InefficientPoint:
    """Memory-inefficient class without __slots__."""
    def __init__(self, x: float, y: float):
        self.x = x
        self.y = y
        # Each instance has a __dict__, using more memory

# ❌ Don't recompute expensive properties
class SlowCircle:
    def __init__(self, radius: float):
        self.radius = radius

    @property
    def area(self) -> float:
        """Recomputes every time - inefficient!"""
        return 3.14159 * self.radius ** 2  # Computed every access

    @property
    def circumference(self) -> float:
        """Recomputes every time - inefficient!"""
        return 2 * 3.14159 * self.radius  # Computed every access

# ❌ Don't use instance methods when static/class methods suffice
class BadMathUtils:
    def add(self, a: float, b: float) -> float:
        """Should be static - doesn't use self."""
        return a + b
```

### Exception Handling Performance

✅ **DO**: Use efficient exception handling

```python
import logging
from typing import Optional, Union

# ✅ Use EAFP (Easier to Ask for Forgiveness than Permission)
def efficient_exception_handling():
    """Efficient exception handling patterns."""

    # Use try/except for expected conditions
    def safe_int_conversion(value: str) -> Optional[int]:
        """Convert string to int safely."""
        try:
            return int(value)
        except ValueError:
            return None

    # Use try/except for dict access when key might not exist
    def get_user_name(user_data: dict) -> str:
        """Get user name with fallback."""
        try:
            return user_data['name']
        except KeyError:
            return "Unknown"

    # Use try/except for file operations
    def read_config_file(filename: str) -> dict:
        """Read config with proper error handling."""
        try:
            with open(filename, 'r') as f:
                import json
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logging.warning(f"Config file error: {e}")
            return {}

# ✅ Specific exception handling
def specific_exception_handling():
    """Handle specific exceptions for better performance."""

    def process_data(data: dict) -> Optional[float]:
        """Process data with specific exception handling."""
        try:
            value = float(data['value'])
            return value / data['divisor']
        except KeyError as e:
            logging.error(f"Missing key: {e}")
            return None
        except (ValueError, TypeError) as e:
            logging.error(f"Invalid data type: {e}")
            return None
        except ZeroDivisionError:
            logging.error("Division by zero")
            return None
        # Don't catch Exception - too broad

# ✅ Exception handling for performance-critical code
def performance_critical_exceptions():
    """Exception handling in performance-critical sections."""

    def fast_lookup_with_fallback(data: dict, keys: list) -> any:
        """Fast lookup with multiple fallbacks."""
        for key in keys:
            try:
                return data[key]  # Try direct access first
            except KeyError:
                continue
        return None

    def batch_process_with_recovery(items: list) -> list:
        """Process batch with individual item recovery."""
        results = []
        for item in items:
            try:
                result = expensive_process(item)
                results.append(result)
            except ProcessingError as e:
                logging.warning(f"Failed to process {item}: {e}")
                results.append(None)  # Continue with remaining items
        return results
```

❌ **DON'T**: Use inefficient exception patterns

```python
# ❌ Don't use exceptions for control flow
def bad_exception_usage():
    """Examples of inefficient exception usage."""

    # Don't use exceptions for expected conditions
    def check_if_number_bad(value: str) -> bool:
        try:
            int(value)
            return True
        except ValueError:
            return False  # Exception used for normal control flow

    # Don't catch overly broad exceptions
    def risky_processing(data):
        try:
            return process_complex_data(data)
        except Exception:  # Too broad - catches everything!
            return None

    # Don't ignore exceptions without logging
    def silent_failure(filename: str):
        try:
            return open(filename).read()
        except:  # Bad - silent failure
            pass

## Part 2: Memory Management and Data Structures

### Memory Optimization Strategies

✅ **DO**: Use memory-efficient patterns and data structures

```python
import sys
import array
import gc
import weakref
from typing import Dict, List, Optional, Iterator, Any
from collections import defaultdict, deque
import struct

# ✅ Use __slots__ to reduce memory overhead
class MemoryEfficientUser:
    """Memory-efficient user class with __slots__."""
    __slots__ = ['id', 'name', 'email', '_cached_data']

    def __init__(self, user_id: int, name: str, email: str):
        self.id = user_id
        self.name = name
        self.email = email
        self._cached_data = None

    def __sizeof__(self) -> int:
        """Calculate actual memory usage."""
        size = object.__sizeof__(self)
        size += sys.getsizeof(self.id)
        size += sys.getsizeof(self.name)
        size += sys.getsizeof(self.email)
        if self._cached_data:
            size += sys.getsizeof(self._cached_data)
        return size

# ✅ Use generators for large datasets
def memory_efficient_data_processing():
    """Process large datasets with generators."""

    def read_large_file_efficiently(filename: str) -> Iterator[str]:
        """Read large files line by line."""
        with open(filename, 'r') as file:
            for line in file:
                yield line.strip()  # Only one line in memory at a time

    def process_numbers_generator(numbers: Iterator[int]) -> Iterator[int]:
        """Process numbers without loading all into memory."""
        for number in numbers:
            if number % 2 == 0:
                yield number * 2

    def batch_generator(items: Iterator[Any], batch_size: int) -> Iterator[List[Any]]:
        """Group items into batches."""
        batch = []
        for item in items:
            batch.append(item)
            if len(batch) >= batch_size:
                yield batch
                batch = []
        if batch:  # Yield remaining items
            yield batch

# ✅ Use array.array for numeric data
def efficient_numeric_storage():
    """Use array.array for memory-efficient numeric storage."""

    # Use array.array instead of list for homogeneous numeric data
    def create_efficient_int_array(size: int) -> array.array:
        """Create memory-efficient integer array."""
        return array.array('i', [0] * size)  # 'i' = signed int (4 bytes each)

    def create_efficient_float_array(values: List[float]) -> array.array:
        """Create memory-efficient float array."""
        return array.array('d', values)  # 'd' = double precision (8 bytes each)

    # Demonstrate memory savings
    regular_list = [i for i in range(1000000)]
    efficient_array = array.array('i', range(1000000))

    print(f"List memory: {sys.getsizeof(regular_list):,} bytes")
    print(f"Array memory: {sys.getsizeof(efficient_array):,} bytes")
    # Array uses ~75% less memory

# ✅ Use struct for binary data
def efficient_binary_data_handling():
    """Handle binary data efficiently with struct."""

    def pack_user_data(user_id: int, age: int, salary: float) -> bytes:
        """Pack user data into binary format."""
        # 'I' = unsigned int (4 bytes), 'H' = unsigned short (2 bytes), 'd' = double (8 bytes)
        return struct.pack('IHd', user_id, age, salary)

    def unpack_user_data(data: bytes) -> tuple[int, int, float]:
        """Unpack binary user data."""
        return struct.unpack('IHd', data)

    # Demonstrate efficiency
    user_data = (12345, 30, 75000.50)
    packed = pack_user_data(*user_data)
    unpacked = unpack_user_data(packed)

    print(f"Original: {user_data}")
    print(f"Packed size: {len(packed)} bytes")
    print(f"Unpacked: {unpacked}")

# ✅ Use weak references to avoid circular references
class EfficientCache:
    """Cache with weak references to avoid memory leaks."""

    def __init__(self):
        self._cache: Dict[str, Any] = {}
        self._weak_refs: Dict[str, weakref.ref] = {}

    def cache_object(self, key: str, obj: Any):
        """Cache object with weak reference tracking."""
        self._cache[key] = obj

        # Create weak reference with cleanup callback
        def cleanup_callback(ref):
            self._cache.pop(key, None)
            self._weak_refs.pop(key, None)

        self._weak_refs[key] = weakref.ref(obj, cleanup_callback)

    def get_cached(self, key: str) -> Optional[Any]:
        """Get cached object if still alive."""
        return self._cache.get(key)

    def cleanup_dead_refs(self):
        """Manually clean up dead references."""
        dead_keys = []
        for key, weak_ref in self._weak_refs.items():
            if weak_ref() is None:  # Object was garbage collected
                dead_keys.append(key)

        for key in dead_keys:
            self._cache.pop(key, None)
            self._weak_refs.pop(key, None)

# ✅ Memory pool pattern for frequent allocations
class ObjectPool:
    """Object pool to reduce allocation overhead."""

    def __init__(self, factory_func, max_size: int = 100):
        self.factory_func = factory_func
        self.pool = deque(maxlen=max_size)
        self.max_size = max_size

    def acquire(self):
        """Get object from pool or create new one."""
        if self.pool:
            return self.pool.popleft()
        return self.factory_func()

    def release(self, obj):
        """Return object to pool."""
        if len(self.pool) < self.max_size:
            # Reset object state before returning to pool
            if hasattr(obj, 'reset'):
                obj.reset()
            self.pool.append(obj)

class PooledBuffer:
    """Reusable buffer object."""

    def __init__(self, size: int = 1024):
        self.buffer = bytearray(size)
        self.length = 0

    def reset(self):
        """Reset buffer for reuse."""
        self.length = 0

    def append(self, data: bytes):
        """Append data to buffer."""
        needed = len(data)
        if self.length + needed > len(self.buffer):
            # Grow buffer if needed
            self.buffer.extend(bytearray(needed))

        self.buffer[self.length:self.length + needed] = data
        self.length += needed

    def get_data(self) -> bytes:
        """Get current buffer data."""
        return bytes(self.buffer[:self.length])

# Usage example
buffer_pool = ObjectPool(lambda: PooledBuffer(1024), max_size=10)
```

❌ **DON'T**: Use memory-inefficient patterns

```python
# ❌ Don't create unnecessary object copies
def inefficient_memory_patterns():
    """Examples of memory-inefficient patterns."""

    # Don't concatenate large strings repeatedly
    def build_large_string_inefficient(parts: List[str]) -> str:
        result = ""
        for part in parts:
            result += part  # Creates new string each time - O(n²) memory
        return result

    # Don't keep references to large objects unnecessarily
    def process_large_data_inefficient():
        large_data = [i for i in range(1000000)]  # Large list
        processed = [x * 2 for x in large_data]  # Both lists in memory
        return processed  # large_data still referenced until function returns

    # Don't use lists when generators suffice
    def get_squares_inefficient(n: int) -> List[int]:
        return [i**2 for i in range(n)]  # All squares in memory at once

    # Don't ignore __slots__ in frequently instantiated classes
    class InefficientUser:
        """Memory-inefficient class without __slots__."""
        def __init__(self, user_id: int, name: str):
            self.id = user_id
            self.name = name
            # Each instance has __dict__ overhead
```

### Garbage Collection Optimization

✅ **DO**: Optimize garbage collection behavior

```python
import gc
import weakref
from typing import Dict, List, Set, Any

# ✅ Manual garbage collection control
class GCOptimizedProcessor:
    """Processor with optimized garbage collection."""

    def __init__(self):
        self.batch_size = 1000
        self.processed_count = 0

    def process_large_dataset(self, dataset: Iterator[Any]):
        """Process large dataset with GC optimization."""
        # Disable automatic GC for performance-critical section
        gc_was_enabled = gc.isenabled()
        gc.disable()

        try:
            batch = []
            for item in dataset:
                batch.append(self.process_item(item))
                self.processed_count += 1

                if len(batch) >= self.batch_size:
                    yield from batch
                    batch.clear()

                    # Manually trigger GC every batch
                    if self.processed_count % (self.batch_size * 10) == 0:
                        collected = gc.collect()
                        if collected > 0:
                            print(f"GC collected {collected} objects")

            # Process remaining items
            if batch:
                yield from batch

        finally:
            # Re-enable GC
            if gc_was_enabled:
                gc.enable()

            # Final cleanup
            gc.collect()

    def process_item(self, item: Any) -> Any:
        """Process individual item."""
        # Simulate processing
        return item * 2 if isinstance(item, (int, float)) else str(item)

# ✅ Circular reference detection and cleanup
class CircularReferenceManager:
    """Manage objects that might create circular references."""

    def __init__(self):
        self.tracked_objects: Set[Any] = set()

    def register_object(self, obj: Any):
        """Register object for tracking."""
        self.tracked_objects.add(obj)

    def cleanup_cycles(self) -> int:
        """Detect and cleanup circular references."""
        # Get current reference counts
        before_count = len(gc.get_objects())

        # Force garbage collection of cycles
        collected = gc.collect()

        # Clean up tracked objects
        dead_objects = set()
        for obj in self.tracked_objects:
            if sys.getrefcount(obj) == 2:  # Only in set and local variable
                dead_objects.add(obj)

        self.tracked_objects -= dead_objects

        after_count = len(gc.get_objects())
        print(f"Cleaned up {before_count - after_count} objects, {collected} cycles")

        return collected

# ✅ Memory monitoring utilities
class MemoryMonitor:
    """Monitor memory usage patterns."""

    def __init__(self):
        self.snapshots = []

    def take_snapshot(self, label: str = ""):
        """Take memory usage snapshot."""
        import psutil
        import os

        process = psutil.Process(os.getpid())
        memory_info = process.memory_info()

        snapshot = {
            'label': label,
            'rss': memory_info.rss,  # Resident Set Size
            'vms': memory_info.vms,  # Virtual Memory Size
            'objects': len(gc.get_objects()),
            'collections': gc.get_stats()
        }

        self.snapshots.append(snapshot)
        return snapshot

    def compare_snapshots(self, start_idx: int = 0, end_idx: int = -1):
        """Compare memory snapshots."""
        if len(self.snapshots) < 2:
            return None

        start = self.snapshots[start_idx]
        end = self.snapshots[end_idx]

        return {
            'rss_diff': end['rss'] - start['rss'],
            'vms_diff': end['vms'] - start['vms'],
            'objects_diff': end['objects'] - start['objects'],
            'start_label': start['label'],
            'end_label': end['label']
        }

    def print_memory_usage(self):
        """Print current memory usage."""
        if self.snapshots:
            latest = self.snapshots[-1]
            print(f"Memory Usage ({latest['label']}):")
            print(f"  RSS: {latest['rss'] / 1024 / 1024:.2f} MB")
            print(f"  VMS: {latest['vms'] / 1024 / 1024:.2f} MB")
            print(f"  Objects: {latest['objects']:,}")

# Example usage
def memory_optimization_example():
    """Example of memory optimization techniques."""

    monitor = MemoryMonitor()
    monitor.take_snapshot("start")

    # Process data with memory optimization
    processor = GCOptimizedProcessor()

    # Simulate large dataset processing
    def generate_data(size: int):
        for i in range(size):
            yield {"id": i, "value": f"item_{i}", "data": [j for j in range(10)]}

    monitor.take_snapshot("before_processing")

    results = list(processor.process_large_dataset(generate_data(10000)))

    monitor.take_snapshot("after_processing")

    # Show memory usage
    diff = monitor.compare_snapshots(0, -1)
    if diff:
        print(f"Memory change: {diff['rss_diff'] / 1024 / 1024:.2f} MB RSS")
        print(f"Object change: {diff['objects_diff']:,} objects")
```

### Data Structure Performance Patterns

✅ **DO**: Choose optimal data structures for performance

```python
import bisect
import heapq
from collections import defaultdict, OrderedDict, Counter, deque
from typing import Dict, List, Tuple, Any, Optional

# ✅ Efficient lookup structures
class OptimizedLookupStructures:
    """Demonstrate efficient lookup patterns."""

    def __init__(self):
        # Use sets for O(1) membership testing
        self.valid_ids: Set[int] = set()

        # Use dicts for O(1) key-value lookup
        self.user_cache: Dict[int, Dict[str, Any]] = {}

        # Use OrderedDict for LRU-like behavior
        self.lru_cache: OrderedDict[str, Any] = OrderedDict()

        # Use defaultdict to avoid KeyError handling
        self.category_items: defaultdict[str, List[Any]] = defaultdict(list)

        # Use Counter for efficient counting
        self.item_counts: Counter[str] = Counter()

    def add_user(self, user_id: int, user_data: Dict[str, Any]):
        """Add user with efficient indexing."""
        self.valid_ids.add(user_id)
        self.user_cache[user_id] = user_data

        # Update category index
        category = user_data.get('category', 'default')
        self.category_items[category].append(user_data)

        # Update counts
        self.item_counts[category] += 1

    def is_valid_user(self, user_id: int) -> bool:
        """O(1) membership test."""
        return user_id in self.valid_ids

    def get_user(self, user_id: int) -> Optional[Dict[str, Any]]:
        """O(1) user lookup."""
        return self.user_cache.get(user_id)

    def get_category_items(self, category: str) -> List[Any]:
        """O(1) category lookup."""
        return self.category_items[category]  # Returns empty list if not found

# ✅ Efficient sorting and searching
class OptimizedSearchSort:
    """Efficient searching and sorting patterns."""

    def __init__(self):
        self.sorted_data: List[Tuple[int, Any]] = []

    def insert_sorted(self, key: int, value: Any):
        """Insert item maintaining sort order - O(n) but keeps sorted."""
        bisect.insort(self.sorted_data, (key, value))

    def find_item(self, key: int) -> Optional[Any]:
        """Binary search in sorted data - O(log n)."""
        index = bisect.bisect_left(self.sorted_data, (key,))
        if index < len(self.sorted_data) and self.sorted_data[index][0] == key:
            return self.sorted_data[index][1]
        return None

    def find_range(self, min_key: int, max_key: int) -> List[Any]:
        """Find all items in key range - O(log n + k)."""
        start_idx = bisect.bisect_left(self.sorted_data, (min_key,))
        end_idx = bisect.bisect_right(self.sorted_data, (max_key,))
        return [item[1] for item in self.sorted_data[start_idx:end_idx]]

# ✅ Priority queue patterns
class TaskQueue:
    """Efficient priority queue implementation."""

    def __init__(self):
        self.heap: List[Tuple[int, int, Any]] = []  # (priority, counter, task)
        self.counter = 0  # Ensures stable sorting for same priorities
        self.task_map: Dict[Any, bool] = {}  # Track valid tasks

    def add_task(self, priority: int, task: Any):
        """Add task with priority - O(log n)."""
        if task in self.task_map:
            # Mark old task as invalid
            self.task_map[task] = False

        # Add new task
        self.counter += 1
        heapq.heappush(self.heap, (priority, self.counter, task))
        self.task_map[task] = True

    def get_next_task(self) -> Optional[Any]:
        """Get highest priority task - O(log n)."""
        while self.heap:
            priority, counter, task = heapq.heappop(self.heap)

            if self.task_map.get(task, False):
                self.task_map[task] = False  # Mark as processed
                return task
            # Skip invalid tasks

        return None

    def is_empty(self) -> bool:
        """Check if queue is empty."""
        # Clean up invalid tasks
        while self.heap and not self.task_map.get(self.heap[0][2], False):
            heapq.heappop(self.heap)

        return len(self.heap) == 0

# ✅ Efficient caching patterns
class LRUCache:
    """Least Recently Used cache implementation."""

    def __init__(self, capacity: int):
        self.capacity = capacity
        self.cache: OrderedDict[Any, Any] = OrderedDict()

    def get(self, key: Any) -> Optional[Any]:
        """Get item and mark as recently used."""
        if key in self.cache:
            # Move to end (most recently used)
            value = self.cache.pop(key)
            self.cache[key] = value
            return value
        return None

    def put(self, key: Any, value: Any):
        """Put item in cache, evicting LRU if necessary."""
        if key in self.cache:
            # Update existing key
            self.cache.pop(key)
        elif len(self.cache) >= self.capacity:
            # Remove least recently used (first item)
            self.cache.popitem(last=False)

        # Add new item (most recently used)
        self.cache[key] = value

    def size(self) -> int:
        """Get current cache size."""
        return len(self.cache)

# ✅ Efficient string processing
class StringProcessor:
    """Efficient string processing patterns."""

    def __init__(self):
        self.string_pool: Dict[str, str] = {}  # String interning

    def intern_string(self, s: str) -> str:
        """Intern strings to save memory."""
        if s not in self.string_pool:
            self.string_pool[s] = s
        return self.string_pool[s]

    def process_text_efficiently(self, text: str) -> Dict[str, int]:
        """Process text with efficient string operations."""
        # Use generator expression with Counter for memory efficiency
        words = (word.lower().strip('.,!?') for word in text.split())
        return Counter(word for word in words if word)

    def build_string_efficiently(self, parts: List[str], separator: str = " ") -> str:
        """Build strings efficiently."""
        return separator.join(parts)  # O(n) instead of O(n²)

    def deduplicate_strings(self, strings: List[str]) -> List[str]:
        """Deduplicate while preserving order."""
        seen = set()
        result = []
        for s in strings:
            if s not in seen:
                seen.add(s)
                result.append(s)
        return result

# Example usage combining all patterns
def efficient_data_processing_example():
    """Example combining multiple efficient patterns."""

    # Initialize efficient data structures
    lookup_structures = OptimizedLookupStructures()
    search_sort = OptimizedSearchSort()
    task_queue = TaskQueue()
    cache = LRUCache(capacity=100)
    string_processor = StringProcessor()

    # Simulate processing pipeline
    sample_data = [
        {"id": i, "name": f"user_{i}", "category": f"cat_{i % 5}", "priority": i % 10}
        for i in range(1000)
    ]

    # Process data efficiently
    for item in sample_data:
        # Add to lookup structures
        lookup_structures.add_user(item["id"], item)

        # Add to sorted structure
        search_sort.insert_sorted(item["priority"], item)

        # Add to task queue
        task_queue.add_task(item["priority"], item)

        # Process strings efficiently
        interned_name = string_processor.intern_string(item["name"])

        # Cache processed results
        processed = {"processed": True, "name": interned_name}
        cache.put(item["id"], processed)

    # Demonstrate efficient operations
    print(f"Valid users: {len(lookup_structures.valid_ids)}")
    print(f"Category counts: {dict(lookup_structures.item_counts)}")
    print(f"High priority items: {len(search_sort.find_range(8, 10))}")
    print(f"Cache size: {cache.size()}")

    # Process tasks by priority
    processed_tasks = []
    while not task_queue.is_empty():
        task = task_queue.get_next_task()
        if task and len(processed_tasks) < 10:  # Process first 10
            processed_tasks.append(task)

    print(f"Processed {len(processed_tasks)} high-priority tasks")

if __name__ == "__main__":
    efficient_data_processing_example()
```
