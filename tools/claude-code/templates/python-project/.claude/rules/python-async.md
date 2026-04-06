# Python Async Programming Standards

**Stack**: asyncio, asyncpg (PostgreSQL), httpx (HTTP), aiofiles (files)

## When to Use Async

✅ **DO**: I/O-bound (database, HTTP, files, network)
❌ **DON'T**: CPU-bound (use `ProcessPoolExecutor`)

## Core Patterns

```python
async def fetch_user(user_id: str) -> dict:
    await asyncio.sleep(0.1)  # Not time.sleep
    return {"id": user_id}

result = await fetch_user("123")
```

**Concurrency:**
- `asyncio.gather()`: Run multiple coroutines
- `asyncio.as_completed()`: Process as ready
- `asyncio.Semaphore()`: Limit concurrency
- `asyncio.Lock()`: Synchronize

**Error Handling:**
```python
async def safe_operation(item_id: str):
    try:
        return await process_item(item_id)
    except asyncio.TimeoutError:
        return None
```

Use `return_exceptions=True` with `gather()`.

## Database Async (AsyncPG)

```python
pool = await asyncpg.create_pool(
    database_url,
    min_size=10,
    max_size=20,
    command_timeout=60
)

async with pool.acquire() as conn:
    rows = await conn.fetch("SELECT * FROM users WHERE id = $1", user_id)
```

**Best Practices:**
- Use pools (min 10, max 20)
- Parameterized queries (`$1`, `$2`)
- Set timeouts (60s)
- Close pools on shutdown

## HTTP Async (HTTPX)

```python
async with httpx.AsyncClient(
    timeout=httpx.Timeout(30.0),
    limits=httpx.Limits(max_connections=100),
    http2=True
) as client:
    response = await client.get("/endpoint")
```

**Rate Limiting:**
```python
async def fetch_multiple(urls: list[str]):
    semaphore = asyncio.Semaphore(10)
    
    async def fetch_one(url: str):
        async with semaphore:
            return await client.get(url)
    
    return await asyncio.gather(*[fetch_one(url) for url in urls])
```

## Event Loop Management

```python
async def main():
    await app.start()
    await app.run()
    await app.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
```

**Graceful Shutdown:**
```python
for task in tasks:
    if not task.done():
        task.cancel()
await asyncio.gather(*tasks, return_exceptions=True)
```

## Common Pitfalls

❌ **DON'T**:
- `time.sleep()` → use `await asyncio.sleep()`
- `requests` → use `httpx` or `aiohttp`
- Forget `await`
- `open()` → use `aiofiles.open()`
- Create unlimited tasks → use semaphores
- Ignore `CancelledError`

✅ **DO**:
- Use async libraries
- Always `await` async functions
- Limit concurrency with `Semaphore`
- Handle `asyncio.CancelledError`
- Use `async with` for resources
- Set timeouts on all I/O

## Performance Tips

**Batch Processing:**
```python
async def process_batch(items: list, batch_size: int = 50):
    for i in range(0, len(items), batch_size):
        batch = items[i:i + batch_size]
        yield await asyncio.gather(*[process(item) for item in batch])
```

**Connection Pooling:**
- Database: Use pools
- HTTP: Reuse sessions

**Memory:**
- Use generators (`async for`)
- Limit concurrent tasks
- Cancel tasks on shutdown

## Testing

```python
@pytest.mark.asyncio
async def test_async_function():
    result = await fetch_user("123")
    assert result["id"] == "123"
```

Configure: `asyncio_mode = "auto"` in pyproject.toml
