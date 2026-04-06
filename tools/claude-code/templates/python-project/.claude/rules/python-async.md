# Python Async Programming Standards

## Overview
Standards for asynchronous programming in Python for I/O-bound operations and concurrent processing.

**Stack**: asyncio, asyncpg (PostgreSQL), httpx (HTTP), aiofiles (files), websockets

## When to Use Async

✅ **DO**: Use async/await for I/O-bound operations
- Database queries and transactions
- HTTP requests and API calls
- File I/O operations
- Network operations and WebSockets
- Message queues and background tasks

❌ **DON'T**: Use async for CPU-bound operations
- Pure computation doesn't benefit from async
- Use `ProcessPoolExecutor` for CPU-intensive work
- Use `run_in_executor()` to offload blocking operations

## Core Patterns

### Async Function Basics
```python
async def fetch_user(user_id: str) -> dict:
    """Always await async functions."""
    await asyncio.sleep(0.1)  # Use asyncio.sleep, not time.sleep
    return {"id": user_id}

# Call async functions
result = await fetch_user("123")  # Must use await
```

### Concurrency Patterns
- `asyncio.gather()`: Run multiple coroutines concurrently
- `asyncio.as_completed()`: Process results as they complete
- `asyncio.wait()`: Wait with timeout and partial results
- `asyncio.Semaphore()`: Limit concurrent operations
- `asyncio.Lock()`: Synchronize access to shared resources

### Error Handling
```python
async def safe_operation(item_id: str):
    try:
        return await process_item(item_id)
    except asyncio.TimeoutError:
        logger.error(f"Timeout for {item_id}")
        return None
    except Exception as e:
        logger.error(f"Failed: {e}")
        raise
```

Use `return_exceptions=True` with `gather()` to handle individual failures.

### Context Managers
```python
class AsyncResource:
    async def __aenter__(self):
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

# Usage
async with AsyncResource() as resource:
    await resource.do_work()
```

## Database Async (AsyncPG)

### Connection Pooling
```python
pool = await asyncpg.create_pool(
    database_url,
    min_size=10,
    max_size=20,
    command_timeout=60
)

# Use pool
async with pool.acquire() as conn:
    rows = await conn.fetch("SELECT * FROM users WHERE id = $1", user_id)
```

### Best Practices
- Use connection pools (min 10, max 20 connections)
- Parameterized queries only (`$1`, `$2` placeholders)
- Use transactions for multiple operations
- Set command timeouts (60 seconds)
- Close pools on shutdown

## HTTP Async (HTTPX)

### Client Configuration
```python
async with httpx.AsyncClient(
    base_url=base_url,
    timeout=httpx.Timeout(30.0),
    limits=httpx.Limits(max_connections=100),
    http2=True
) as client:
    response = await client.get("/endpoint")
    data = response.json()
```

### Concurrent Requests
```python
async def fetch_multiple(urls: list[str]) -> list[dict]:
    semaphore = asyncio.Semaphore(10)  # Max 10 concurrent
    
    async def fetch_one(url: str):
        async with semaphore:
            return await client.get(url)
    
    results = await asyncio.gather(*[fetch_one(url) for url in urls])
    return results
```

### Best Practices
- Set connection limits (max 100 connections)
- Set timeouts (30 seconds default)
- Use semaphores for rate limiting
- Enable HTTP/2 for better performance
- Retry with exponential backoff for transient errors

## Event Loop Management

### Proper Lifecycle
```python
async def main():
    # Setup
    app = Application()
    await app.start()
    
    # Run
    await app.run()
    
    # Cleanup
    await app.cleanup()

if __name__ == "__main__":
    asyncio.run(main())  # Handles event loop lifecycle
```

### Task Management
```python
# Create tracked tasks
task = asyncio.create_task(background_work(), name="worker")

# Graceful shutdown
for task in tasks:
    if not task.done():
        task.cancel()

await asyncio.gather(*tasks, return_exceptions=True)
```

## Common Pitfalls

❌ **DON'T**:
- Block event loop with `time.sleep()` - use `await asyncio.sleep()`
- Use `requests` library - use `httpx` or `aiohttp`
- Forget `await` on async functions
- Use `open()` for files - use `aiofiles.open()`
- Create unlimited tasks - use semaphores
- Ignore `CancelledError` - handle and re-raise
- Mix sync and async database drivers

✅ **DO**:
- Use `await asyncio.sleep()` for delays
- Use async libraries (httpx, asyncpg, aiofiles)
- Always `await` async functions
- Limit concurrent operations with `Semaphore`
- Handle `asyncio.CancelledError` properly
- Use `async with` for resource management
- Set timeouts on all I/O operations

## Performance Tips

### Batch Processing
```python
async def process_batch(items: list, batch_size: int = 50):
    for i in range(0, len(items), batch_size):
        batch = items[i:i + batch_size]
        results = await asyncio.gather(*[process(item) for item in batch])
        yield results
```

### Connection Pooling
- Database: Use connection pools (not per-request connections)
- HTTP: Reuse client sessions (not per-request clients)
- WebSocket: Maintain persistent connections

### Memory Management
- Use generators for large datasets (`async for`)
- Limit concurrent tasks with semaphores
- Clean up resources in `finally` blocks
- Cancel tasks on shutdown

## Testing Async Code

### pytest-asyncio
```python
import pytest

@pytest.mark.asyncio
async def test_async_function():
    result = await fetch_user("123")
    assert result["id"] == "123"

# Configure
# pytest.ini: asyncio_mode = auto
```

### Mocking
```python
async def test_with_mock(mocker):
    mock_db = mocker.patch('app.database.fetch')
    mock_db.return_value = {"id": "123"}
    
    result = await service.get_user("123")
    assert result["id"] == "123"
```

## Debugging

### Enable asyncio debug mode
```python
import asyncio
asyncio.run(main(), debug=True)
```

### Detect slow callbacks
```python
# Set warning threshold
import warnings
warnings.simplefilter('always', ResourceWarning)
```

### Log task exceptions
```python
def exception_handler(loop, context):
    logging.error(f"Task exception: {context}")

loop = asyncio.get_event_loop()
loop.set_exception_handler(exception_handler)
```

## References
- [asyncio Documentation](https://docs.python.org/3/library/asyncio.html)
- [AsyncPG](https://magicstack.github.io/asyncpg/)
- [HTTPX](https://www.python-httpx.org/)
- [aiohttp](https://docs.aiohttp.org/)
- [aiofiles](https://github.com/Tinche/aiofiles)
- [pytest-asyncio](https://pytest-asyncio.readthedocs.io/)
