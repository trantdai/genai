# Performance Analysis Workflow

## When to Use
When experiencing performance issues, before optimization work, or during performance reviews.

## Prerequisites
- [ ] Profiling tools installed: `cProfile`, `line_profiler`, `memory_profiler`, `py-spy`
- [ ] Test dataset or production-like workload
- [ ] Performance baseline metrics

## Quick Performance Check

```bash
# Install tools
pip install line-profiler memory-profiler py-spy

# Quick profile
python -m cProfile -s cumulative script.py > profile.txt

# Memory profile
python -m memory_profiler script.py
```

## Identify Performance Issues

- [ ] Slow response times
- [ ] High memory usage
- [ ] High CPU usage
- [ ] Slow database queries
- [ ] Network latency
- [ ] Large memory allocations

## Profile Application

### CPU Profiling
```bash
# cProfile - function-level
python -m cProfile -s cumulative script.py > profile.txt

# line_profiler - line-level
@profile  # Add decorator
python -m line_profiler script.py.lprof

# py-spy - sampling profiler (no code changes)
py-spy record --rate 100 --native --output profile.svg -- python script.py
```

### Memory Profiling
```bash
# memory_profiler - line-level
@profile  # Add decorator
python -m memory_profiler script.py

# tracemalloc - built-in
import tracemalloc
tracemalloc.start()
# ... code to profile
snapshot = tracemalloc.take_snapshot()
```

## Analyze Profile Results

- [ ] Identify top time-consuming functions (>5% total time)
- [ ] Find memory allocation hot spots
- [ ] Check for unnecessary object creation
- [ ] Identify N+1 query patterns
- [ ] Look for nested loops (O(n²) or worse)
- [ ] Find blocking I/O operations

## Common Performance Issues

### Algorithm Complexity
- [ ] Check time complexity (should be O(n log n) max)
- [ ] Use appropriate data structures (dict/set for lookups)
- [ ] Avoid nested loops when possible
- [ ] Use binary search on sorted data

### Data Structure Issues
- [ ] Using list for membership testing (use set)
- [ ] Repeated dict key checks
- [ ] String concatenation in loops
- [ ] Not using generators for large datasets

### Database Performance
- [ ] Missing indexes on query columns
- [ ] N+1 query problem
- [ ] Not using connection pooling
- [ ] Loading too much data at once
- [ ] Missing query optimization

### Memory Issues
- [ ] Large objects kept in memory
- [ ] Not using __slots__ for classes
- [ ] Loading entire files into memory
- [ ] Circular references preventing GC
- [ ] Creating objects in tight loops

## Optimization Strategies

### Quick Wins
- [ ] Use `@lru_cache` for expensive functions
- [ ] Replace lists with sets for membership testing
- [ ] Use list comprehensions instead of loops
- [ ] Cache attribute lookups in loops
- [ ] Use `str.join()` instead of concatenation

### Data Structure Optimization
- [ ] Use dict for O(1) lookups instead of list
- [ ] Use set for O(1) membership testing
- [ ] Use deque for queue operations
- [ ] Use Counter for counting operations
- [ ] Use defaultdict to avoid KeyError checks

### Algorithm Optimization
- [ ] Replace O(n²) with O(n log n) algorithms
- [ ] Use binary search on sorted data
- [ ] Batch database operations
- [ ] Use generators for large datasets
- [ ] Parallelize independent operations

### Memory Optimization
- [ ] Use __slots__ for frequently instantiated classes
- [ ] Use generators instead of lists
- [ ] Use array.array for homogeneous numeric data
- [ ] Release large objects explicitly
- [ ] Use weak references where appropriate

## Database Optimization

- [ ] Add indexes to frequently queried columns
- [ ] Use select_related/prefetch_related (ORM)
- [ ] Batch queries with gather/asyncio
- [ ] Use connection pooling
- [ ] Optimize query execution plans
- [ ] Cache frequently accessed data

## Async Optimization

- [ ] Use async for I/O-bound operations
- [ ] Limit concurrency with Semaphore
- [ ] Use connection pools for HTTP/DB
- [ ] Batch operations when possible
- [ ] Set appropriate timeouts

## Benchmark Changes

```python
import timeit

# Before optimization
time_before = timeit.timeit('old_function()', number=1000)

# After optimization
time_after = timeit.timeit('new_function()', number=1000)

speedup = time_before / time_after
print(f"Speedup: {speedup:.2f}x")
```

## Verify Improvements

- [ ] Re-run profiler to confirm improvements
- [ ] Measure actual performance gains
- [ ] Check memory usage reduction
- [ ] Verify correctness (run tests)
- [ ] Compare before/after metrics
- [ ] Document optimization results

## Performance Testing

```bash
# Load testing
pip install locust
locust -f locustfile.py

# Stress testing
pip install pytest-benchmark
pytest benchmarks/ --benchmark-only
```

## Performance Checklist

- [ ] Profile identified bottlenecks
- [ ] Optimized hot paths (>5% total time)
- [ ] Appropriate data structures used
- [ ] Algorithm complexity optimal
- [ ] Database queries optimized
- [ ] Caching implemented where appropriate
- [ ] Memory usage reduced
- [ ] Tests still passing
- [ ] Performance metrics improved
- [ ] Documentation updated

## Performance Targets

**Response Times**:
- API endpoints: <100ms (p95), <500ms (p99)
- Database queries: <50ms per query
- Background jobs: Complete within SLA

**Resource Usage**:
- Memory: <1GB per worker
- CPU: <70% average
- Database connections: <80% pool capacity

## References
- [Python Performance Tips](https://wiki.python.org/moin/PythonSpeed/PerformanceTips)
- [cProfile docs](https://docs.python.org/3/library/profile.html)
- [line_profiler](https://github.com/pyutils/line_profiler)
- [memory_profiler](https://pypi.org/project/memory-profiler/)
- [py-spy](https://github.com/benfred/py-spy)
