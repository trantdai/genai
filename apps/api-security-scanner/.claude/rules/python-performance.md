# Python Performance Standards

**Key Principle**: Measure before optimizing. Profile to find bottlenecks.

## Data Structure Selection

✅ **DO**:
- `set` for O(1) membership testing
- `dict` for O(1) key-value lookup
- `collections.deque` for queue operations
- `collections.Counter` for counting
- `collections.defaultdict` to avoid KeyError

❌ **DON'T**:
- `list` for membership testing (O(n) lookup)
- String concatenation in loops (use `str.join()`)

## String Operations

✅ **DO**: `" ".join(parts)`, f-strings, `startswith()`/`endswith()`
❌ **DON'T**: `result += part` in loops

## Function Optimization

```python
import functools

@functools.lru_cache(maxsize=128)
def expensive_calculation(n: int) -> int:
    # Caches results
    pass
```

**Use built-ins** (C implementation): `sum()`, `max()`, `min()`, `any()`, `all()`

## Memory Optimization

**__slots__:**
```python
class EfficientClass:
    __slots__ = ['x', 'y', 'z']  # ~60% less memory
```

**Generators:**
```python
def process_large_file(filename: str):
    with open(filename) as f:
        for line in f:
            yield process(line)
```

## Loop Optimization

✅ **DO**: List comprehensions, `enumerate()`, `zip()`
```python
squares = [x**2 for x in numbers if x > 0]
total = sum(x**2 for x in numbers if x > 0)  # Generator for memory
```

## Profiling

```bash
python -m cProfile -s cumulative script.py
python -m line_profiler script.py.lprof  # Line-level
python -m memory_profiler script.py      # Memory
```

## Caching

```python
@functools.lru_cache(maxsize=128)
def expensive_function(n: int) -> float:
    return complex_calculation(n)
```

## Concurrency

- **I/O-bound**: Use `asyncio` (preferred) or `ThreadPoolExecutor`
- **CPU-bound**: Use `ProcessPoolExecutor`

## Checklist

- [ ] Profile to identify bottlenecks
- [ ] Use appropriate data structures (set, dict, deque)
- [ ] Cache expensive computations
- [ ] Use generators for large datasets
- [ ] Implement __slots__ for frequent classes
- [ ] Use async for I/O operations
- [ ] Batch database queries
- [ ] Add database indexes
- [ ] Use connection pooling
- [ ] Set timeouts

## Anti-Patterns

❌ **Avoid**:
- Premature optimization without profiling
- String concatenation in loops
- Lists for membership testing
- Nested loops when set operations work
- Repeated database queries in loops
- Loading entire files into memory
- Not caching expensive computations
