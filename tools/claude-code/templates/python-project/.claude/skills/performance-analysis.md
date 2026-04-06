# Performance Analysis Workflow

## Tools
`cProfile`, `line_profiler`, `memory_profiler`, `py-spy`

## Steps

### 1. Profile Application
- [ ] CPU: `python -m cProfile -s cumulative script.py`
- [ ] Memory: `memory_profiler` with @profile decorator
- [ ] Sampling: `py-spy record` (no code changes)

### 2. Analyze Results
- [ ] Identify top functions (>5% total time)
- [ ] Find N+1 query patterns
- [ ] Check for nested loops (O(n²))
- [ ] Identify blocking I/O operations

### 3. Optimize
- [ ] Use dict/set for O(1) lookups
- [ ] Apply @lru_cache for expensive functions
- [ ] Use generators for large datasets
- [ ] Add database indexes
- [ ] Use async for I/O operations
- [ ] Implement connection pooling

### 4. Verify
- [ ] Re-run profiler
- [ ] Measure performance gains
- [ ] Run tests

## Performance Targets
- API: <100ms (p95), <500ms (p99)
- Database: <50ms
- Memory: <1GB per worker
- CPU: <70% average

See: [`.claude/rules/python-performance.md`](../rules/python-performance.md)
