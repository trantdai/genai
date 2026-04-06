# Python Performance Standards

## Overview
Performance optimization requires profiling first, then choosing appropriate algorithms, data structures, and patterns.

**Key Principle**: Measure before optimizing. Profile to find bottlenecks.

## Performance Mindset

1. **Profile First**: Always profile before optimizing
2. **Algorithmic Efficiency**: Choose optimal algorithms and data structures
3. **Memory Awareness**: Understand memory usage patterns
4. **I/O Optimization**: Minimize blocking operations
5. **Caching**: Implement smart caching strategies

## Algorithm & Data Structure Selection

### Choose Optimal Data Structures

✅ **DO**:
```python
# Use sets for O(1) membership testing
valid_ids = {1, 2, 3, 4, 5}  # O(1) lookup
if user_id in valid_ids:  # Fast

# Use dict for O(1) key-value lookup
user_cache = {123: user_data}  # O(1) access

# Use collections.deque for queue operations
from collections import deque
queue = deque()
queue.append(item)  # O(1)
queue.popleft()  # O(1)

# Use collections.Counter for counting
from collections import Counter
counts = Counter(items)  # Efficient counting

# Use collections.defaultdict to avoid KeyError
from collections import defaultdict
groups = defaultdict(list)
groups[key].append(value)  # No KeyError
```

❌ **DON'T**:
```python
# Don't use lists for membership testing
valid_ids = [1, 2, 3, 4, 5]  # O(n) lookup
if user_id in valid_ids:  # Slow for large lists

# Don't repeatedly check dict keys
if key in data:  # Redundant check
    data[key] += 1
else:
    data[key] = 1
```

### String Operations

✅ **DO**:
```python
# Use str.join() for concatenation
result = " ".join(parts)  # O(n)

# Use f-strings for formatting
message = f"User {name} has {count} items"  # Fastest

# Use str methods for operations
text.startswith(prefix)  # Faster than slicing
text.endswith(suffix)
```

❌ **DON'T**:
```python
# Don't concatenate in loops
result = ""
for part in parts:
    result += part  # O(n²) - creates new string each time
```

### Function Optimization

✅ **DO**:
```python
import functools

# Cache expensive computations
@functools.lru_cache(maxsize=128)
def fibonacci(n: int) -> int:
    if n < 2:
        return 1
    return fibonacci(n-1) + fibonacci(n-2)

# Use built-in functions (implemented in C)
total = sum(numbers)  # Faster than loop
maximum = max(numbers)

# Cache attribute lookups in loops
result = []
append = result.append  # Cache method reference
for item in items:
    append(process(item))  # Faster access
```

## Memory Optimization

### Use __slots__ for Classes

✅ **DO**:
```python
class EfficientPoint:
    __slots__ = ['x', 'y', 'z']
    
    def __init__(self, x: float, y: float, z: float = 0.0):
        self.x = x
        self.y = y
        self.z = z
# Uses ~60% less memory than without __slots__
```

### Use Generators for Large Data

✅ **DO**:
```python
def read_large_file(filename: str):
    """Generator - only one line in memory."""
    with open(filename) as f:
        for line in f:
            yield line.strip()

# Process in batches
def batch_generator(items, batch_size: int):
    batch = []
    for item in items:
        batch.append(item)
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch
```

### Efficient Numeric Storage

✅ **DO**:
```python
import array

# Use array.array for homogeneous numeric data
numbers = array.array('i', range(1000000))  # 75% less memory than list
floats = array.array('d', [1.0, 2.0, 3.0])  # Double precision
```

## Loop Optimization

✅ **DO**:
```python
# Use list comprehensions
squares = [x**2 for x in numbers if x > 0]  # Fast

# Use generator expressions for memory efficiency
total = sum(x**2 for x in numbers if x > 0)  # Memory efficient

# Use enumerate instead of range(len())
for i, item in enumerate(items):
    process(i, item)

# Use zip for parallel iteration
for name, age in zip(names, ages):
    process(name, age)
```

❌ **DON'T**:
```python
# Don't use complex list comprehensions
results = [
    complex_calc(x) if validate(x) and check(x)
    else default(x) if x > threshold
    else fallback
    for x in items
]  # Too complex - use regular loop
```

## Import Optimization

✅ **DO**:
```python
# Import only what you need
from collections import defaultdict, Counter

# Use local imports for rarely used modules
def process_json(data: str):
    import json  # Local import
    return json.loads(data)

# Pre-compile regex at module level
import re
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
```

## Profiling

### cProfile for Function Profiling
```bash
python -m cProfile -s cumulative script.py > profile.txt
```

### line_profiler for Line-by-Line
```bash
pip install line_profiler
@profile  # Decorator
python -m line_profiler script.py.lprof
```

### memory_profiler for Memory Usage
```bash
pip install memory_profiler
@profile  # Decorator
python -m memory_profiler script.py
```

### timeit for Microbenchmarks
```python
import timeit

# Compare approaches
time1 = timeit.timeit('sum(range(100))', number=10000)
time2 = timeit.timeit('list(range(100))', number=10000)
```

## Caching Strategies

### functools.lru_cache
```python
@functools.lru_cache(maxsize=128)
def expensive_function(n: int) -> float:
    return complex_calculation(n)
```

### Custom Cache with TTL
```python
class TTLCache:
    def __init__(self, ttl_seconds: int = 300):
        self.cache = {}
        self.ttl = ttl_seconds
    
    def get(self, key):
        if key in self.cache:
            value, timestamp = self.cache[key]
            if time.time() - timestamp < self.ttl:
                return value
        return None
    
    def set(self, key, value):
        self.cache[key] = (value, time.time())
```

## Concurrency

### Threading for I/O-Bound
```python
from concurrent.futures import ThreadPoolExecutor

with ThreadPoolExecutor(max_workers=10) as executor:
    results = list(executor.map(io_bound_task, items))
```

### Multiprocessing for CPU-Bound
```python
from concurrent.futures import ProcessPoolExecutor

with ProcessPoolExecutor(max_workers=4) as executor:
    results = list(executor.map(cpu_bound_task, items))
```

### Async for I/O-Bound (Preferred)
```python
import asyncio

async def process_items(items):
    tasks = [process_item(item) for item in items]
    return await asyncio.gather(*tasks)
```

## Common Performance Patterns

### Object Pooling
```python
class ObjectPool:
    def __init__(self, factory, max_size=100):
        self.factory = factory
        self.pool = deque(maxlen=max_size)
    
    def acquire(self):
        return self.pool.pop() if self.pool else self.factory()
    
    def release(self, obj):
        if hasattr(obj, 'reset'):
            obj.reset()
        self.pool.append(obj)
```

### Lazy Loading
```python
class LazyProperty:
    def __init__(self, func):
        self.func = func
    
    def __get__(self, obj, type=None):
        if obj is None:
            return self
        value = self.func(obj)
        setattr(obj, self.func.__name__, value)
        return value
```

## Performance Checklist

Before deployment:
- [ ] Profile code to identify bottlenecks
- [ ] Use appropriate data structures (set, dict, deque)
- [ ] Cache expensive computations
- [ ] Use generators for large datasets
- [ ] Implement __slots__ for frequently instantiated classes
- [ ] Use async for I/O-bound operations
- [ ] Minimize database queries (use batching)
- [ ] Add indexes to database tables
- [ ] Use connection pooling
- [ ] Set appropriate timeouts

## Anti-Patterns

❌ **Avoid**:
- Premature optimization without profiling
- String concatenation in loops
- Lists for membership testing on large datasets
- Nested loops when set operations work
- Repeated database queries in loops
- Loading entire large files into memory
- Creating objects in tight loops
- Not caching expensive computations

## References
- [Python Performance Tips](https://wiki.python.org/moin/PythonSpeed/PerformanceTips)
- [High Performance Python (O'Reilly)](https://www.oreilly.com/library/view/high-performance-python/9781492055013/)
- [cProfile Documentation](https://docs.python.org/3/library/profile.html)
- [line_profiler](https://github.com/pyutils/line_profiler)
- [memory_profiler](https://pypi.org/project/memory-profiler/)
