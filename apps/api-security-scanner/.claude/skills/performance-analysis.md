# Performance Analysis Workflow

## When to Use
Use this skill to identify performance bottlenecks, optimize slow code, analyze memory usage, and improve application efficiency. Run when experiencing performance issues or as part of regular optimization cycles.

## Prerequisites
- Python project with performance concerns
- Profiling tools installed:
  - `cProfile` (built-in)
  - `memory_profiler` for memory analysis
  - `py-spy` for production profiling
  - `line_profiler` for line-by-line profiling
- Virtual environment activated
- Representative test data or workload

## Workflow Steps

### 1. Setup Profiling Environment
```bash
cd /path/to/project
source .venv/bin/activate

# Install profiling tools
pip install memory_profiler py-spy line_profiler
```

### 2. Profile Code Execution (CPU Time)
```bash
# Profile with cProfile (built-in)
python -m cProfile -o profile.stats -s cumulative src/main.py

# View results
python -m pstats profile.stats
# In pstats shell:
# sort cumulative
# stats 20  # Show top 20 functions

# Or use snakeviz for visual analysis
pip install snakeviz
snakeviz profile.stats
```

**What to Look For**:
- Functions with high cumulative time
- Functions called many times
- Unexpected bottlenecks
- I/O operations blocking execution
- Inefficient algorithms

**Example Output Analysis**:
```
   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
     1000    2.500    0.003    5.000    0.005 module.py:10(slow_function)
   100000    1.200    0.000    1.200    0.000 utils.py:5(helper)
```

### 3. Line-by-Line Profiling
```bash
# Add @profile decorator to functions you want to profile
# No import needed - line_profiler adds it at runtime
```

```python
# example.py
@profile
def process_data(data):
    result = []
    for item in data:
        processed = expensive_operation(item)
        result.append(processed)
    return result
```

```bash
# Run line profiler
kernprof -l -v src/example.py

# View results
python -m line_profiler example.py.lprof
```

**Example Output**:
```
Line #      Hits         Time  Per Hit   % Time  Line Contents
==============================================================
     3                                           @profile
     4                                           def process_data(data):
     5         1          2.0      2.0      0.0      result = []
     6      1000        500.0      0.5      5.0      for item in data:
     7      1000       9000.0      9.0     90.0          processed = expensive_operation(item)
     8      1000        500.0      0.5      5.0          result.append(processed)
     9         1          0.0      0.0      0.0      return result
```

### 4. Analyze Memory Usage
```bash
# Profile memory usage
python -m memory_profiler src/main.py

# Or use mprof for time-based memory tracking
mprof run src/main.py
mprof plot
```

**Add memory profiling to code**:
```python
from memory_profiler import profile

@profile
def memory_intensive_function():
    large_list = [i for i in range(1000000)]
    large_dict = {i: i**2 for i in range(100000)}
    return process(large_list, large_dict)
```

**What to Look For**:
- Memory leaks (continuously growing memory)
- Large object allocations
- Unnecessary data copies
- Objects not being garbage collected
- Memory spikes during operations

### 5. Check Database Query Performance
```bash
# Enable SQL query logging
# For SQLAlchemy:
```

```python
import logging
logging.basicConfig()
logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)

# Or use query profiling
from sqlalchemy import event
from sqlalchemy.engine import Engine
import time

@event.listens_for(Engine, "before_cursor_execute")
def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    conn.info.setdefault('query_start_time', []).append(time.time())

@event.listens_for(Engine, "after_cursor_execute")
def after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    total = time.time() - conn.info['query_start_time'].pop(-1)
    if total > 0.1:  # Log slow queries (>100ms)
        print(f"Slow query ({total:.2f}s): {statement}")
```

**Database Performance Checklist**:
- [ ] Identify slow queries (>100ms)
- [ ] Check for missing indexes
- [ ] Look for N+1 query problems
- [ ] Verify query plan efficiency
- [ ] Check for unnecessary joins
- [ ] Optimize WHERE clauses
- [ ] Use query result caching

### 6. Identify N+1 Query Problems
```bash
# Search for potential N+1 patterns
grep -r "for.*in.*:" src/ --include="*.py" -A 5 | grep -i "query\|select\|filter"
```

**N+1 Problem Example**:
```python
# ❌ BAD - N+1 queries
users = session.query(User).all()
for user in users:  # 1 query
    posts = user.posts  # N queries (one per user)
    print(f"{user.name}: {len(posts)} posts")

# ✅ GOOD - Single query with eager loading
users = session.query(User).options(joinedload(User.posts)).all()
for user in users:  # 1 query total
    print(f"{user.name}: {len(user.posts)} posts")
```

### 7. Review Async/Await Usage
```bash
# Search for async patterns
grep -r "async def\|await\|asyncio" src/ --include="*.py"
```

**Async Performance Checklist**:
- [ ] I/O-bound operations use async/await
- [ ] CPU-bound operations don't block event loop
- [ ] Proper use of asyncio.gather() for concurrency
- [ ] No blocking calls in async functions
- [ ] Async context managers used correctly
- [ ] Connection pooling for async database access

**Example Optimization**:
```python
# ❌ BAD - Sequential async calls
async def fetch_all_data():
    data1 = await fetch_data_1()
    data2 = await fetch_data_2()
    data3 = await fetch_data_3()
    return data1, data2, data3

# ✅ GOOD - Concurrent async calls
async def fetch_all_data():
    results = await asyncio.gather(
        fetch_data_1(),
        fetch_data_2(),
        fetch_data_3()
    )
    return results
```

### 8. Benchmark Critical Paths
```python
# Create benchmark script
import timeit
from functools import wraps
import time

def benchmark(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        end = time.perf_counter()
        print(f"{func.__name__} took {end - start:.4f} seconds")
        return result
    return wrapper

@benchmark
def critical_function():
    # Your code here
    pass

# Or use timeit for precise measurements
def test_performance():
    setup = "from __main__ import my_function"
    stmt = "my_function(test_data)"
    time = timeit.timeit(stmt, setup, number=1000)
    print(f"Average time: {time/1000:.6f} seconds")
```

### 9. Generate Optimization Recommendations
```bash
# Create performance analysis report
cat > performance-report.md << 'EOF'
# Performance Analysis Report
**Date**: $(date +%Y-%m-%d)
**Analyst**: $(git config user.name)

## Executive Summary
<!-- Overview of performance findings -->

## Profiling Results

### CPU Profiling
- Total execution time: X seconds
- Top bottlenecks:
  1. Function A: X seconds (X%)
  2. Function B: X seconds (X%)
  3. Function C: X seconds (X%)

### Memory Profiling
- Peak memory usage: X MB
- Memory leaks detected: Yes/No
- Large allocations: X MB in function Y

### Database Performance
- Total queries: X
- Slow queries (>100ms): X
- N+1 problems detected: X
- Missing indexes: X

## Identified Issues

### Critical Performance Issues
1. <!-- Issue description, impact, location -->

### Optimization Opportunities
1. <!-- Opportunity description, expected improvement -->

## Recommendations

### Immediate Actions (High Impact)
1. <!-- Specific recommendation with code example -->

### Medium Priority
1. <!-- Recommendation -->

### Long-term Improvements
1. <!-- Strategic recommendation -->

## Benchmarks

### Before Optimization
- Metric 1: X
- Metric 2: X

### After Optimization (Expected)
- Metric 1: X (X% improvement)
- Metric 2: X (X% improvement)

## Next Steps
1. <!-- Action items -->
EOF
```

### 10. Production Profiling with py-spy
```bash
# Profile running Python process (no code changes needed)
# Find process ID
ps aux | grep python

# Profile for 60 seconds
sudo py-spy record -o profile.svg --pid <PID> --duration 60

# View flame graph
open profile.svg

# Or use top-like interface
sudo py-spy top --pid <PID>
```

## Success Criteria
- ✅ Performance bottlenecks identified
- ✅ Memory usage analyzed and optimized
- ✅ Database queries optimized (no N+1 problems)
- ✅ Async/await used correctly for I/O operations
- ✅ Critical paths benchmarked
- ✅ Optimization recommendations documented
- ✅ Performance improvements measured
- ✅ No memory leaks detected

## Common Issues

### Issue: Profiling overhead affects results
**Solution**:
- Use sampling profilers (py-spy) for production
- Profile with representative data, not production load
- Run multiple iterations and average results
- Use deterministic profiling for development only

### Issue: Memory profiler too slow
**Solution**:
```python
# Use memory_profiler selectively
@profile
def only_profile_this_function():
    pass

# Or use tracemalloc (built-in, faster)
import tracemalloc
tracemalloc.start()
# Your code here
snapshot = tracemalloc.take_snapshot()
top_stats = snapshot.statistics('lineno')
for stat in top_stats[:10]:
    print(stat)
```

### Issue: Can't identify bottleneck
**Solution**:
1. Start with high-level profiling (cProfile)
2. Narrow down to specific modules
3. Use line_profiler for detailed analysis
4. Check I/O operations separately
5. Profile with different data sizes

### Issue: Database queries slow but no N+1
**Solution**:
```sql
-- Check query execution plan
EXPLAIN ANALYZE SELECT ...;

-- Add missing indexes
CREATE INDEX idx_user_email ON users(email);

-- Optimize query structure
-- Use LIMIT for pagination
-- Avoid SELECT *
-- Use appropriate JOIN types
```

## Examples

### Example 1: Quick Performance Check
```python
# quick_profile.py
import cProfile
import pstats
from main import main_function

profiler = cProfile.Profile()
profiler.enable()

main_function()

profiler.disable()
stats = pstats.Stats(profiler)
stats.sort_stats('cumulative')
stats.print_stats(20)
```

### Example 2: Memory Leak Detection
```python
import tracemalloc
import gc

tracemalloc.start()

# Take snapshot before
snapshot1 = tracemalloc.take_snapshot()

# Run your code
for i in range(100):
    potentially_leaky_function()
    gc.collect()

# Take snapshot after
snapshot2 = tracemalloc.take_snapshot()

# Compare
top_stats = snapshot2.compare_to(snapshot1, 'lineno')
print("[ Top 10 differences ]")
for stat in top_stats[:10]:
    print(stat)
```

### Example 3: Async Performance Optimization
```python
import asyncio
import time

# Before optimization
async def slow_version():
    start = time.time()
    result1 = await fetch_data_1()  # 1 second
    result2 = await fetch_data_2()  # 1 second
    result3 = await fetch_data_3()  # 1 second
    print(f"Slow version: {time.time() - start:.2f}s")  # ~3 seconds
    return result1, result2, result3

# After optimization
async def fast_version():
    start = time.time()
    results = await asyncio.gather(
        fetch_data_1(),
        fetch_data_2(),
        fetch_data_3()
    )
    print(f"Fast version: {time.time() - start:.2f}s")  # ~1 second
    return results
```

## Related Skills
- [`code-review-workflow.md`](./code-review-workflow.md) - Review performance in code reviews
- [`refactoring-workflow.md`](./refactoring-workflow.md) - Refactor for performance
- [`tdd-workflow.md`](./tdd-workflow.md) - Write performance tests

## Best Practices
- Profile before optimizing (measure, don't guess)
- Focus on bottlenecks (80/20 rule)
- Optimize algorithms before micro-optimizations
- Use appropriate data structures
- Cache expensive computations
- Use lazy evaluation where possible
- Batch database operations
- Use connection pooling
- Implement pagination for large datasets
- Monitor performance in production
- Set performance budgets
- Automate performance testing
- Document performance requirements
- Use CDN for static assets
- Implement proper caching strategies
