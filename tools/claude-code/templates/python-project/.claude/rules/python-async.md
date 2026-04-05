# Python Async Programming Rules

## Overview
This document defines best practices and standards for asynchronous programming in Python. Async programming is essential for I/O-bound operations, concurrent processing, and building scalable applications that can handle multiple operations simultaneously.

## When to Use Async/Await

### Appropriate Use Cases
✅ **DO**: Use async/await for I/O-bound operations
- **Database operations**: Queries, transactions, connection pooling
- **HTTP requests**: API calls, web scraping, external service integration
- **File I/O**: Reading/writing large files, file processing
- **Network operations**: Socket programming, message queues
- **WebSocket connections**: Real-time communication
- **Background tasks**: Scheduled jobs, data processing pipelines

### When NOT to Use Async
❌ **DON'T**: Use async for CPU-bound operations without proper consideration
```python
# Wrong - CPU-intensive work doesn't benefit from async
async def cpu_intensive_task():
    result = 0
    for i in range(10_000_000):  # Pure CPU work
        result += i * i
    return result

# Better - Use multiprocessing or threading for CPU-bound tasks
import multiprocessing
from concurrent.futures import ProcessPoolExecutor

def cpu_intensive_task():
    result = 0
    for i in range(10_000_000):
        result += i * i
    return result

async def run_cpu_task():
    loop = asyncio.get_event_loop()
    with ProcessPoolExecutor() as executor:
        result = await loop.run_in_executor(executor, cpu_intensive_task)
    return result
```

## Basic Async Patterns

### Function Definition and Calling
✅ **DO**: Properly define and call async functions
```python
import asyncio
from typing import List, Optional, Dict, Any

# Correct async function definition
async def fetch_user_data(user_id: str) -> Optional[Dict[str, Any]]:
    """Fetch user data asynchronously."""
    # Simulate async I/O operation
    await asyncio.sleep(0.1)  # Replace with actual async call
    return {"id": user_id, "name": "User Name"}

# Correct way to call async functions
async def main():
    # Single async call
    user = await fetch_user_data("123")

    # Multiple concurrent calls
    user_ids = ["123", "456", "789"]
    users = await asyncio.gather(*[
        fetch_user_data(user_id) for user_id in user_ids
    ])

    return users

# Run the async function
if __name__ == "__main__":
    result = asyncio.run(main())
```

❌ **DON'T**: Mix sync and async incorrectly
```python
# Wrong - calling async function without await
def bad_function():
    result = fetch_user_data("123")  # Returns coroutine, not data!
    return result

# Wrong - using await outside async function
def another_bad_function():
    result = await fetch_user_data("123")  # SyntaxError!
    return result

# Wrong - blocking the event loop
async def blocking_function():
    time.sleep(5)  # Blocks entire event loop!
    return "done"
```

### Error Handling in Async Code
✅ **DO**: Implement proper error handling for async operations
```python
import asyncio
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)

async def safe_async_operation(item_id: str) -> Optional[Dict[str, Any]]:
    """Safely perform async operation with error handling."""
    try:
        # Simulate async operation that might fail
        if item_id == "invalid":
            raise ValueError(f"Invalid item ID: {item_id}")

        await asyncio.sleep(0.1)
        return {"id": item_id, "status": "success"}

    except asyncio.TimeoutError:
        logger.error(f"Timeout processing item {item_id}")
        return None

    except ValueError as e:
        logger.error(f"Validation error for item {item_id}: {e}")
        return None

    except Exception as e:
        logger.error(f"Unexpected error processing item {item_id}: {e}")
        return None

async def process_items_safely(item_ids: List[str]) -> List[Dict[str, Any]]:
    """Process multiple items with individual error handling."""
    tasks = [safe_async_operation(item_id) for item_id in item_ids]

    # Use asyncio.gather with return_exceptions=True
    results = await asyncio.gather(*tasks, return_exceptions=True)

    successful_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            logger.error(f"Item {item_ids[i]} failed: {result}")
        elif result is not None:
            successful_results.append(result)

    return successful_results

# Usage with timeout
async def main_with_timeout():
    try:
        # Set overall timeout for the operation
        result = await asyncio.wait_for(
            process_items_safely(["1", "2", "invalid", "3"]),
            timeout=5.0
        )
        return result

    except asyncio.TimeoutError:
        logger.error("Overall operation timed out")
        return []
```

### Concurrent Execution Patterns
✅ **DO**: Use appropriate concurrency patterns
```python
import asyncio
from typing import List, Tuple, Any
import time

async def fetch_data(url: str, delay: float = 0.1) -> str:
    """Simulate fetching data from a URL."""
    await asyncio.sleep(delay)
    return f"Data from {url}"

# Pattern 1: asyncio.gather() - All tasks must succeed
async def fetch_all_or_fail(urls: List[str]) -> List[str]:
    """Fetch all URLs, fail if any fails."""
    results = await asyncio.gather(*[
        fetch_data(url) for url in urls
    ])
    return results

# Pattern 2: asyncio.gather() with error handling
async def fetch_all_with_errors(urls: List[str]) -> List[str]:
    """Fetch all URLs, handle individual failures."""
    results = await asyncio.gather(*[
        fetch_data(url) for url in urls
    ], return_exceptions=True)

    successful_results = []
    for url, result in zip(urls, results):
        if isinstance(result, Exception):
            logger.error(f"Failed to fetch {url}: {result}")
        else:
            successful_results.append(result)

    return successful_results

# Pattern 3: asyncio.as_completed() - Process results as they complete
async def fetch_as_completed(urls: List[str]) -> List[str]:
    """Process results as they become available."""
    tasks = [fetch_data(url) for url in urls]
    results = []

    for coro in asyncio.as_completed(tasks):
        try:
            result = await coro
            results.append(result)
            print(f"Completed: {result}")
        except Exception as e:
            logger.error(f"Task failed: {e}")

    return results

# Pattern 4: Semaphore for rate limiting
async def fetch_with_rate_limit(urls: List[str], max_concurrent: int = 5) -> List[str]:
    """Fetch URLs with concurrency limit."""
    semaphore = asyncio.Semaphore(max_concurrent)

    async def fetch_with_semaphore(url: str) -> str:
        async with semaphore:
            return await fetch_data(url)

    results = await asyncio.gather(*[
        fetch_with_semaphore(url) for url in urls
    ], return_exceptions=True)

    return [r for r in results if not isinstance(r, Exception)]

# Pattern 5: asyncio.wait() with timeout and partial results
async def fetch_with_timeout(urls: List[str], timeout: float = 2.0) -> Tuple[List[str], List[str]]:
    """Fetch URLs with timeout, return completed and pending."""
    tasks = [asyncio.create_task(fetch_data(url)) for url in urls]

    done, pending = await asyncio.wait(
        tasks,
        timeout=timeout,
        return_when=asyncio.FIRST_EXCEPTION
    )

    # Process completed tasks
    completed_results = []
    for task in done:
        try:
            result = await task
            completed_results.append(result)
        except Exception as e:
            logger.error(f"Task failed: {e}")

    # Cancel pending tasks
    pending_urls = []
    for i, task in enumerate(tasks):
        if task in pending:
            task.cancel()
            pending_urls.append(urls[i])

    return completed_results, pending_urls
```

### Async Context Managers
✅ **DO**: Use async context managers for resource management
```python
import asyncio
import aiofiles
from typing import AsyncGenerator, Optional
from contextlib import asynccontextmanager

class AsyncDatabaseConnection:
    """Example async database connection."""

    def __init__(self, connection_string: str):
        self.connection_string = connection_string
        self.connection = None

    async def __aenter__(self):
        """Async context manager entry."""
        print(f"Connecting to {self.connection_string}")
        await asyncio.sleep(0.1)  # Simulate connection time
        self.connection = f"Connected to {self.connection_string}"
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.connection:
            print("Closing database connection")
            await asyncio.sleep(0.05)  # Simulate cleanup time
            self.connection = None

    async def execute_query(self, query: str) -> str:
        """Execute a database query."""
        if not self.connection:
            raise RuntimeError("Not connected to database")

        await asyncio.sleep(0.1)  # Simulate query execution
        return f"Result for: {query}"

# Using async context manager
async def database_operations():
    async with AsyncDatabaseConnection("postgresql://localhost/mydb") as db:
        result1 = await db.execute_query("SELECT * FROM users")
        result2 = await db.execute_query("SELECT * FROM products")
        return [result1, result2]

# Async context manager for file operations
async def process_file_async(filename: str) -> str:
    """Process file using async file I/O."""
    async with aiofiles.open(filename, 'r') as file:
        content = await file.read()
        # Process content asynchronously
        await asyncio.sleep(0.1)  # Simulate processing
        return content.upper()

# Custom async context manager using decorator
@asynccontextmanager
async def async_timer() -> AsyncGenerator[None, None]:
    """Async context manager to time operations."""
    start_time = time.time()
    try:
        yield
    finally:
        end_time = time.time()
        print(f"Operation took {end_time - start_time:.2f} seconds")

# Usage of custom async context manager
async def timed_operation():
    async with async_timer():
        await asyncio.sleep(1)
        print("Operation completed")
```

### Async Generators and Iterators
✅ **DO**: Use async generators for streaming data
```python
import asyncio
from typing import AsyncGenerator, List, Optional
import json

async def async_data_stream(count: int) -> AsyncGenerator[Dict[str, Any], None]:
    """Generate data items asynchronously."""
    for i in range(count):
        # Simulate async data fetching
        await asyncio.sleep(0.1)
        yield {
            "id": i,
            "timestamp": time.time(),
            "data": f"Item {i}"
        }

async def process_data_stream(stream: AsyncGenerator[Dict[str, Any], None]) -> List[Dict[str, Any]]:
    """Process async data stream."""
    results = []
    async for item in stream:
        # Process each item as it arrives
        processed_item = {
            **item,
            "processed": True,
            "processed_at": time.time()
        }
        results.append(processed_item)

        # Optional: Add backpressure handling
        if len(results) % 10 == 0:
            print(f"Processed {len(results)} items")

    return results

# Async iterator with pagination
class AsyncPaginatedIterator:
    """Async iterator for paginated data."""

    def __init__(self, total_items: int, page_size: int = 10):
        self.total_items = total_items
        self.page_size = page_size
        self.current_page = 0

    def __aiter__(self):
        return self

    async def __anext__(self) -> List[Dict[str, Any]]:
        start_idx = self.current_page * self.page_size

        if start_idx >= self.total_items:
            raise StopAsyncIteration

        end_idx = min(start_idx + self.page_size, self.total_items)

        # Simulate async data fetching
        await asyncio.sleep(0.1)

        page_data = [
            {"id": i, "value": f"Item {i}"}
            for i in range(start_idx, end_idx)
        ]

        self.current_page += 1
        return page_data

# Usage of async iterator
async def process_paginated_data():
    async_iter = AsyncPaginatedIterator(total_items=50, page_size=10)

    all_items = []
    async for page in async_iter:
        print(f"Processing page with {len(page)} items")
        all_items.extend(page)

    return all_items

## Database Async Patterns

### AsyncPG for PostgreSQL
✅ **DO**: Use asyncpg for high-performance PostgreSQL operations
```python
import asyncpg
import asyncio
from typing import List, Dict, Any, Optional
from contextlib import asynccontextmanager

class AsyncPostgreSQLClient:
    """Async PostgreSQL client with connection pooling."""

    def __init__(self, database_url: str, min_size: int = 10, max_size: int = 20):
        self.database_url = database_url
        self.min_size = min_size
        self.max_size = max_size
        self.pool: Optional[asyncpg.Pool] = None

    async def create_pool(self) -> None:
        """Create connection pool."""
        self.pool = await asyncpg.create_pool(
            self.database_url,
            min_size=self.min_size,
            max_size=self.max_size,
            command_timeout=60
        )

    async def close_pool(self) -> None:
        """Close connection pool."""
        if self.pool:
            await self.pool.close()

    @asynccontextmanager
    async def get_connection(self):
        """Get connection from pool with context manager."""
        if not self.pool:
            raise RuntimeError("Pool not initialized")

        async with self.pool.acquire() as connection:
            yield connection

    async def fetch_one(self, query: str, *args) -> Optional[Dict[str, Any]]:
        """Fetch single record."""
        async with self.get_connection() as conn:
            row = await conn.fetchrow(query, *args)
            return dict(row) if row else None

    async def fetch_all(self, query: str, *args) -> List[Dict[str, Any]]:
        """Fetch multiple records."""
        async with self.get_connection() as conn:
            rows = await conn.fetch(query, *args)
            return [dict(row) for row in rows]

    async def execute(self, query: str, *args) -> str:
        """Execute query that doesn't return data."""
        async with self.get_connection() as conn:
            return await conn.execute(query, *args)

    async def execute_many(self, query: str, args_list: List[tuple]) -> None:
        """Execute query multiple times with different parameters."""
        async with self.get_connection() as conn:
            await conn.executemany(query, args_list)

    async def transaction(self, queries_and_params: List[tuple]) -> None:
        """Execute multiple queries in a transaction."""
        async with self.get_connection() as conn:
            async with conn.transaction():
                for query, params in queries_and_params:
                    await conn.execute(query, *params)

# Usage example
async def database_operations():
    db = AsyncPostgreSQLClient("postgresql://user:pass@localhost/db")
    await db.create_pool()

    try:
        # Single record fetch
        user = await db.fetch_one(
            "SELECT * FROM users WHERE id = $1",
            123
        )

        # Multiple records
        active_users = await db.fetch_all(
            "SELECT * FROM users WHERE active = $1 LIMIT $2",
            True, 100
        )

        # Insert with transaction
        await db.transaction([
            ("INSERT INTO users (name, email) VALUES ($1, $2)", ("John", "john@example.com")),
            ("UPDATE user_stats SET total_users = total_users + 1", ())
        ])

    finally:
        await db.close_pool()
```

### SQLAlchemy Async Support
✅ **DO**: Use SQLAlchemy with async engines
```python
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import select, update, delete, Integer, String, Boolean
from typing import List, Optional
import asyncio

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    email: Mapped[str] = mapped_column(String(255), unique=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)

class AsyncUserRepository:
    """Async repository for User operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID."""
        stmt = select(User).where(User.id == user_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_active_users(self, limit: int = 100) -> List[User]:
        """Get active users with limit."""
        stmt = select(User).where(User.active == True).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def create_user(self, name: str, email: str) -> User:
        """Create new user."""
        user = User(name=name, email=email)
        self.session.add(user)
        await self.session.commit()
        await self.session.refresh(user)
        return user

    async def update_user(self, user_id: int, **kwargs) -> Optional[User]:
        """Update user by ID."""
        stmt = update(User).where(User.id == user_id).values(**kwargs)
        await self.session.execute(stmt)
        await self.session.commit()
        return await self.get_by_id(user_id)

    async def delete_user(self, user_id: int) -> bool:
        """Delete user by ID."""
        stmt = delete(User).where(User.id == user_id)
        result = await self.session.execute(stmt)
        await self.session.commit()
        return result.rowcount > 0

class AsyncDatabaseManager:
    """Async database manager with session factory."""

    def __init__(self, database_url: str):
        self.engine = create_async_engine(
            database_url,
            pool_size=20,
            max_overflow=0,
            echo=False  # Set to True for SQL logging
        )
        self.async_session = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False
        )

    @asynccontextmanager
    async def get_session(self):
        """Get database session with context manager."""
        async with self.async_session() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise

    async def close(self):
        """Close database engine."""
        await self.engine.dispose()

# Usage example
async def sqlalchemy_operations():
    db_manager = AsyncDatabaseManager("postgresql+asyncpg://user:pass@localhost/db")

    try:
        async with db_manager.get_session() as session:
            user_repo = AsyncUserRepository(session)

            # Create user
            new_user = await user_repo.create_user("Alice", "alice@example.com")
            print(f"Created user: {new_user.id}")

            # Get user
            user = await user_repo.get_by_id(new_user.id)
            print(f"Retrieved user: {user.name}")

            # Update user
            updated_user = await user_repo.update_user(user.id, name="Alice Smith")
            print(f"Updated user: {updated_user.name}")

            # Get active users
            active_users = await user_repo.get_active_users(limit=10)
            print(f"Active users count: {len(active_users)}")

    finally:
        await db_manager.close()
```

## HTTP Client Async Patterns

### HTTPX for Async HTTP Requests
✅ **DO**: Use httpx for async HTTP operations
```python
import httpx
import asyncio
from typing import List, Dict, Any, Optional
import time
import logging

logger = logging.getLogger(__name__)

class AsyncHTTPClient:
    """Async HTTP client with best practices."""

    def __init__(
        self,
        base_url: str = "",
        timeout: float = 30.0,
        max_connections: int = 100,
        max_keepalive_connections: int = 20
    ):
        # Configure connection limits
        limits = httpx.Limits(
            max_connections=max_connections,
            max_keepalive_connections=max_keepalive_connections
        )

        # Configure timeout
        timeout_config = httpx.Timeout(timeout)

        self.client = httpx.AsyncClient(
            base_url=base_url,
            timeout=timeout_config,
            limits=limits,
            http2=True  # Enable HTTP/2 support
        )

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()

    async def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Make GET request with error handling."""
        try:
            response = await self.client.get(
                url,
                params=params,
                headers=headers
            )
            response.raise_for_status()
            return response.json()

        except httpx.TimeoutException:
            logger.error(f"Timeout for GET {url}")
            raise

        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error {e.response.status_code} for GET {url}")
            raise

        except Exception as e:
            logger.error(f"Unexpected error for GET {url}: {e}")
            raise

    async def post(
        self,
        url: str,
        json_data: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Make POST request with error handling."""
        try:
            response = await self.client.post(
                url,
                json=json_data,
                data=data,
                headers=headers
            )
            response.raise_for_status()
            return response.json()

        except httpx.TimeoutException:
            logger.error(f"Timeout for POST {url}")
            raise

        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error {e.response.status_code} for POST {url}")
            raise

    async def fetch_multiple(
        self,
        urls: List[str],
        max_concurrent: int = 10
    ) -> List[Optional[Dict[str, Any]]]:
        """Fetch multiple URLs concurrently with rate limiting."""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def fetch_with_semaphore(url: str) -> Optional[Dict[str, Any]]:
            async with semaphore:
                try:
                    return await self.get(url)
                except Exception as e:
                    logger.error(f"Failed to fetch {url}: {e}")
                    return None

        results = await asyncio.gather(*[
            fetch_with_semaphore(url) for url in urls
        ], return_exceptions=True)

        return [r if not isinstance(r, Exception) else None for r in results]

# Advanced HTTP patterns
class APIClient:
    """Advanced API client with retry, caching, and authentication."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.api_key = api_key
        self.session_cache: Dict[str, Any] = {}

        self.client = httpx.AsyncClient(
            base_url=base_url,
            timeout=httpx.Timeout(30.0),
            limits=httpx.Limits(max_connections=50)
        )

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with authentication."""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "AsyncAPIClient/1.0"
        }

    async def _make_request_with_retry(
        self,
        method: str,
        url: str,
        max_retries: int = 3,
        backoff_factor: float = 1.0,
        **kwargs
    ) -> httpx.Response:
        """Make request with exponential backoff retry."""
        for attempt in range(max_retries + 1):
            try:
                response = await self.client.request(
                    method,
                    url,
                    headers=self._get_headers(),
                    **kwargs
                )

                # Retry on server errors (5xx)
                if response.status_code >= 500 and attempt < max_retries:
                    wait_time = backoff_factor * (2 ** attempt)
                    logger.warning(
                        f"Server error {response.status_code}, retrying in {wait_time}s"
                    )
                    await asyncio.sleep(wait_time)
                    continue

                response.raise_for_status()
                return response

            except (httpx.TimeoutException, httpx.ConnectError) as e:
                if attempt < max_retries:
                    wait_time = backoff_factor * (2 ** attempt)
                    logger.warning(f"Request failed: {e}, retrying in {wait_time}s")
                    await asyncio.sleep(wait_time)
                    continue
                raise

        raise Exception(f"Max retries exceeded for {method} {url}")

    async def get_with_cache(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        cache_ttl: int = 300
    ) -> Dict[str, Any]:
        """GET request with simple in-memory caching."""
        cache_key = f"{endpoint}:{str(params)}"

        # Check cache
        if cache_key in self.session_cache:
            cached_data, timestamp = self.session_cache[cache_key]
            if time.time() - timestamp < cache_ttl:
                return cached_data

        # Make request
        response = await self._make_request_with_retry(
            "GET",
            endpoint,
            params=params
        )

        data = response.json()

        # Cache result
        self.session_cache[cache_key] = (data, time.time())

        return data

    async def batch_requests(
        self,
        requests: List[Dict[str, Any]],
        max_concurrent: int = 10
    ) -> List[Optional[Dict[str, Any]]]:
        """Execute batch of API requests with concurrency control."""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def execute_request(request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            async with semaphore:
                try:
                    method = request.get("method", "GET")
                    endpoint = request["endpoint"]
                    params = request.get("params")
                    json_data = request.get("json")

                    response = await self._make_request_with_retry(
                        method,
                        endpoint,
                        params=params,
                        json=json_data
                    )

                    return response.json()

                except Exception as e:
                    logger.error(f"Batch request failed: {e}")
                    return None

        results = await asyncio.gather(*[
            execute_request(req) for req in requests
        ], return_exceptions=True)

        return [r if not isinstance(r, Exception) else None for r in results]

# Usage examples
async def http_client_examples():
    # Basic usage
    async with AsyncHTTPClient("https://jsonplaceholder.typicode.com") as client:
        # Single request
        post = await client.get("/posts/1")
        print(f"Post title: {post['title']}")

        # Multiple concurrent requests
        urls = [f"/posts/{i}" for i in range(1, 6)]
        posts = await client.fetch_multiple(urls, max_concurrent=3)
        valid_posts = [p for p in posts if p is not None]
        print(f"Fetched {len(valid_posts)} posts")

    # Advanced API client
    async with APIClient("https://api.example.com", "your-api-key") as api:
        # Cached request
        data = await api.get_with_cache("/users/profile", cache_ttl=600)

        # Batch requests
        batch_requests = [
            {"method": "GET", "endpoint": "/users/1"},
            {"method": "GET", "endpoint": "/users/2"},
            {"method": "POST", "endpoint": "/users", "json": {"name": "New User"}},
        ]

        results = await api.batch_requests(batch_requests, max_concurrent=5)
        successful_results = [r for r in results if r is not None]
        print(f"Batch completed: {len(successful_results)} successful")
```

### WebSocket Async Patterns
✅ **DO**: Use websockets library for real-time communication
```python
import websockets
import asyncio
import json
import logging
from typing import Dict, Any, Callable, Optional
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)

class AsyncWebSocketClient:
    """Async WebSocket client with reconnection and message handling."""

    def __init__(
        self,
        uri: str,
        max_reconnect_attempts: int = 5,
        reconnect_delay: float = 1.0
    ):
        self.uri = uri
        self.max_reconnect_attempts = max_reconnect_attempts
        self.reconnect_delay = reconnect_delay
        self.websocket = None
        self.message_handlers: Dict[str, Callable] = {}
        self.running = False

    def register_handler(self, message_type: str, handler: Callable):
        """Register message handler for specific message type."""
        self.message_handlers[message_type] = handler

    async def connect(self) -> None:
        """Connect to WebSocket with retry logic."""
        for attempt in range(self.max_reconnect_attempts):
            try:
                self.websocket = await websockets.connect(self.uri)
                logger.info(f"WebSocket connected to {self.uri}")
                return

            except Exception as e:
                logger.error(f"Connection attempt {attempt + 1} failed: {e}")
                if attempt < self.max_reconnect_attempts - 1:
                    await asyncio.sleep(self.reconnect_delay * (2 ** attempt))
                else:
                    raise ConnectionError(f"Failed to connect after {self.max_reconnect_attempts} attempts")

    async def disconnect(self) -> None:
        """Disconnect from WebSocket."""
        self.running = False
        if self.websocket:
            await self.websocket.close()
            self.websocket = None

    async def send_message(self, message: Dict[str, Any]) -> None:
        """Send message to WebSocket."""
        if not self.websocket:
            raise RuntimeError("WebSocket not connected")

        try:
            await self.websocket.send(json.dumps(message))
        except websockets.exceptions.ConnectionClosed:
            logger.error("WebSocket connection closed, attempting reconnect...")
            await self.connect()
            await self.websocket.send(json.dumps(message))

    async def listen(self) -> None:
        """Listen for incoming messages."""
        self.running = True

        while self.running:
            try:
                if not self.websocket:
                    await self.connect()

                async for message in self.websocket:
                    try:
                        data = json.loads(message)
                        message_type = data.get("type", "unknown")

                        if message_type in self.message_handlers:
                            await self.message_handlers[message_type](data)
                        else:
                            logger.warning(f"Unhandled message type: {message_type}")

                    except json.JSONDecodeError:
                        logger.error(f"Invalid JSON received: {message}")

                    except Exception as e:
                        logger.error(f"Error processing message: {e}")

            except websockets.exceptions.ConnectionClosed:
                logger.warning("WebSocket connection lost, attempting reconnect...")
                await asyncio.sleep(self.reconnect_delay)
                if self.running:
                    try:
                        await self.connect()
                    except ConnectionError:
                        logger.error("Reconnection failed, stopping listener")
                        break

            except Exception as e:
                logger.error(f"Unexpected error in WebSocket listener: {e}")
                await asyncio.sleep(self.reconnect_delay)

# Usage example
async def websocket_example():
    client = AsyncWebSocketClient("wss://echo.websocket.org")

    # Register message handlers
    async def handle_echo(data):
        print(f"Received echo: {data}")

    async def handle_status(data):
        print(f"Status update: {data}")

    client.register_handler("echo", handle_echo)
    client.register_handler("status", handle_status)

    try:
        # Start listening in background
        listen_task = asyncio.create_task(client.listen())

        # Send some messages
        await client.send_message({"type": "echo", "text": "Hello WebSocket!"})
        await asyncio.sleep(1)

        await client.send_message({"type": "status", "message": "Client connected"})
        await asyncio.sleep(2)

    finally:
        await client.disconnect()
        listen_task.cancel()
        try:
            await listen_task
        except asyncio.CancelledError:
            pass
```

## Part 3: Event Loop Management and Context Managers

### Event Loop Best Practices

✅ **DO**: Use proper event loop lifecycle management

```python
import asyncio
import signal
from contextlib import asynccontextmanager
from typing import Optional

class AsyncAppManager:
    def __init__(self):
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.shutdown_event = asyncio.Event()

    async def start(self):
        """Start the application with proper signal handling."""
        # Set up signal handlers for graceful shutdown
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, self._signal_handler)

        # Start background tasks
        await self._start_background_tasks()

        # Wait for shutdown signal
        await self.shutdown_event.wait()

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        print(f"Received signal {signum}, initiating shutdown...")
        if self.loop:
            self.loop.call_soon_threadsafe(self.shutdown_event.set)

    async def _start_background_tasks(self):
        """Start background tasks with proper error handling."""
        tasks = [
            asyncio.create_task(self._health_check_task()),
            asyncio.create_task(self._cleanup_task()),
        ]

        # Store task references to prevent garbage collection
        self.background_tasks = set(tasks)

        # Add done callback to clean up completed tasks
        for task in tasks:
            task.add_done_callback(self.background_tasks.discard)

# Usage
async def main():
    app = AsyncAppManager()
    try:
        await app.start()
    except KeyboardInterrupt:
        print("Application interrupted")
    finally:
        # Clean shutdown
        await app.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
```

❌ **DON'T**: Create multiple event loops or access loop from wrong thread

```python
# ❌ Don't create multiple loops
import asyncio

def bad_event_loop_usage():
    # This creates a new event loop, potentially conflicting with existing one
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Don't access event loop from different thread without proper synchronization
    def thread_function():
        asyncio.get_event_loop().call_soon(some_callback)  # Will fail!

# ❌ Don't block the event loop
async def blocking_operation():
    import time
    time.sleep(10)  # This blocks the entire event loop!
```

### Async Context Managers

✅ **DO**: Implement proper async context managers for resource management

```python
import asyncio
import aiofiles
import aiohttp
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional
import logging

class AsyncDatabasePool:
    def __init__(self, connection_string: str, pool_size: int = 10):
        self.connection_string = connection_string
        self.pool_size = pool_size
        self.pool: Optional[asyncpg.Pool] = None

    async def __aenter__(self):
        """Async context manager entry."""
        self.pool = await asyncpg.create_pool(
            self.connection_string,
            min_size=1,
            max_size=self.pool_size,
            command_timeout=60,
            server_settings={
                'jit': 'off',  # Disable JIT for faster connection
            }
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit with proper cleanup."""
        if self.pool:
            await self.pool.close()

        # Handle exceptions if needed
        if exc_type:
            logging.error(f"Database context manager error: {exc_val}")

        return False  # Don't suppress exceptions

    async def execute_query(self, query: str, *args) -> list[dict]:
        """Execute query using the pool."""
        if not self.pool:
            raise RuntimeError("Database pool not initialized")

        async with self.pool.acquire() as connection:
            rows = await connection.fetch(query, *args)
            return [dict(row) for row in rows]

# Resource management context manager
@asynccontextmanager
async def managed_resources(
    db_url: str,
    api_base_url: str
) -> AsyncGenerator[tuple[AsyncDatabasePool, aiohttp.ClientSession], None]:
    """Context manager for multiple async resources."""
    db_pool = None
    http_session = None

    try:
        # Initialize database pool
        db_pool = AsyncDatabasePool(db_url)
        await db_pool.__aenter__()

        # Initialize HTTP session
        timeout = aiohttp.ClientTimeout(total=30)
        http_session = aiohttp.ClientSession(
            base_url=api_base_url,
            timeout=timeout,
            connector=aiohttp.TCPConnector(limit=100)
        )

        yield db_pool, http_session

    except Exception as e:
        logging.error(f"Error in managed resources: {e}")
        raise
    finally:
        # Cleanup resources in reverse order
        if http_session:
            await http_session.close()

        if db_pool:
            await db_pool.__aexit__(None, None, None)

# File processing context manager
@asynccontextmanager
async def async_file_processor(
    file_path: str,
    mode: str = 'r'
) -> AsyncGenerator[aiofiles.threadpool.AsyncTextIOWrapper, None]:
    """Context manager for async file operations."""
    file_handle = None
    try:
        file_handle = await aiofiles.open(file_path, mode=mode)
        yield file_handle
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        raise
    except PermissionError:
        logging.error(f"Permission denied: {file_path}")
        raise
    finally:
        if file_handle:
            await file_handle.close()

# Usage examples
async def example_usage():
    """Example of using async context managers."""

    # Using database pool context manager
    async with AsyncDatabasePool("postgresql://...") as db:
        users = await db.execute_query("SELECT * FROM users WHERE active = $1", True)
        print(f"Found {len(users)} active users")

    # Using multi-resource context manager
    async with managed_resources(
        "postgresql://...",
        "https://api.example.com"
    ) as (db, http):
        # Both resources are available and will be cleaned up automatically
        users = await db.execute_query("SELECT id FROM users LIMIT 10")

        for user in users:
            async with http.get(f"/user/{user['id']}/profile") as response:
                profile = await response.json()
                # Process profile data

    # Using file processor
    async with async_file_processor("large_file.txt") as file:
        async for line in file:
            # Process line asynchronously
            await process_line(line)
```

❌ **DON'T**: Forget to properly handle cleanup or use blocking operations in context managers

```python
# ❌ Poor context manager implementation
class BadAsyncContextManager:
    async def __aenter__(self):
        self.resource = SomeResource()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        # Missing proper cleanup!
        # What if self.resource is None?
        # What if cleanup fails?
        self.resource.close()  # Should be await if it's async!

# ❌ Don't use blocking operations in async context managers
@asynccontextmanager
async def bad_context_manager():
    resource = blocking_resource_creation()  # Blocks event loop!
    try:
        yield resource
    finally:
        blocking_cleanup(resource)  # Blocks event loop!
```

### Task and Coroutine Management

✅ **DO**: Properly manage tasks and handle cancellation

```python
import asyncio
from contextlib import asynccontextmanager
from typing import Set, Optional
import logging

class TaskManager:
    def __init__(self):
        self.tasks: Set[asyncio.Task] = set()
        self._shutdown = False

    def create_task(self, coro, *, name: Optional[str] = None) -> asyncio.Task:
        """Create and track a task."""
        if self._shutdown:
            raise RuntimeError("TaskManager is shutting down")

        task = asyncio.create_task(coro, name=name)
        self.tasks.add(task)

        # Automatically remove completed tasks
        task.add_done_callback(self.tasks.discard)
        task.add_done_callback(self._log_task_completion)

        return task

    def _log_task_completion(self, task: asyncio.Task):
        """Log task completion and any exceptions."""
        if task.cancelled():
            logging.info(f"Task {task.get_name()} was cancelled")
        elif task.exception():
            logging.error(f"Task {task.get_name()} failed", exc_info=task.exception())
        else:
            logging.debug(f"Task {task.get_name()} completed successfully")

    async def shutdown(self, timeout: float = 10.0):
        """Gracefully shutdown all tasks."""
        self._shutdown = True

        if not self.tasks:
            return

        logging.info(f"Shutting down {len(self.tasks)} tasks...")

        # Cancel all tasks
        for task in self.tasks:
            if not task.done():
                task.cancel()

        # Wait for tasks to complete or timeout
        try:
            await asyncio.wait_for(
                asyncio.gather(*self.tasks, return_exceptions=True),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            logging.warning(f"Some tasks didn't complete within {timeout}s timeout")

        # Force cleanup of remaining tasks
        for task in self.tasks:
            if not task.done():
                logging.warning(f"Force cancelling task: {task.get_name()}")
                task.cancel()

        self.tasks.clear()

# Background task with proper error handling
async def background_worker(task_manager: TaskManager, queue: asyncio.Queue):
    """Background worker that processes queue items."""

    async def process_item(item):
        try:
            # Simulate processing
            await asyncio.sleep(0.1)

            if item.get("error"):
                raise ValueError(f"Processing error: {item['error']}")

            logging.info(f"Processed item: {item['id']}")

        except Exception as e:
            logging.error(f"Failed to process item {item.get('id', 'unknown')}: {e}")
            # Optionally re-queue or handle error

    while True:
        try:
            # Wait for item with timeout to allow periodic checks
            item = await asyncio.wait_for(queue.get(), timeout=1.0)

            # Process in separate task to avoid blocking queue processing
            task_manager.create_task(
                process_item(item),
                name=f"process-{item.get('id', 'unknown')}"
            )

            # Mark task as done
            queue.task_done()

        except asyncio.TimeoutError:
            # Periodic check for shutdown signal
            if task_manager._shutdown:
                break
        except asyncio.CancelledError:
            logging.info("Background worker cancelled")
            break
        except Exception as e:
            logging.error(f"Unexpected error in background worker: {e}")
            await asyncio.sleep(1)  # Brief pause before retry

@asynccontextmanager
async def application_context():
    """Application context with proper task management."""
    task_manager = TaskManager()
    queue = asyncio.Queue(maxsize=100)

    try:
        # Start background workers
        worker_tasks = [
            task_manager.create_task(
                background_worker(task_manager, queue),
                name=f"worker-{i}"
            )
            for i in range(3)  # 3 worker tasks
        ]

        yield task_manager, queue

    finally:
        # Graceful shutdown
        logging.info("Shutting down application...")

        # Stop accepting new items
        await queue.join()  # Wait for remaining items to be processed

        # Shutdown all tasks
        await task_manager.shutdown(timeout=30.0)

# Usage example
async def main():
    async with application_context() as (task_manager, queue):
        # Add some work items
        for i in range(10):
            await queue.put({"id": i, "data": f"item-{i}"})

        # Create additional tasks
        monitor_task = task_manager.create_task(
            monitor_system_health(),
            name="health-monitor"
        )

        # Simulate running for a while
        await asyncio.sleep(5)

        # Context manager handles cleanup automatically

if __name__ == "__main__":
    asyncio.run(main())
```

### Advanced Async Patterns

✅ **DO**: Use proper semaphores and locks for concurrency control

```python
import asyncio
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional
import time

class RateLimitedResource:
    """Resource with rate limiting and concurrent access control."""

    def __init__(self, max_concurrent: int = 5, rate_limit: float = 10.0):
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.rate_limit = rate_limit
        self.last_access = 0.0
        self.access_lock = asyncio.Lock()

    @asynccontextmanager
    async def acquire(self):
        """Acquire resource with rate limiting."""
        async with self.semaphore:  # Limit concurrent access
            async with self.access_lock:  # Ensure rate limiting
                now = time.time()
                time_since_last = now - self.last_access

                if time_since_last < (1.0 / self.rate_limit):
                    wait_time = (1.0 / self.rate_limit) - time_since_last
                    await asyncio.sleep(wait_time)

                self.last_access = time.time()

            try:
                yield self
            finally:
                # Resource cleanup if needed
                pass

# Async cache with TTL
class AsyncTTLCache:
    """Async cache with time-to-live expiration."""

    def __init__(self, ttl_seconds: float = 300):
        self.cache: Dict[str, tuple[Any, float]] = {}
        self.ttl_seconds = ttl_seconds
        self.lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache if not expired."""
        async with self.lock:
            if key in self.cache:
                value, timestamp = self.cache[key]
                if time.time() - timestamp < self.ttl_seconds:
                    return value
                else:
                    del self.cache[key]
            return None

    async def set(self, key: str, value: Any):
        """Set value in cache with current timestamp."""
        async with self.lock:
            self.cache[key] = (value, time.time())

    async def cleanup_expired(self):
        """Remove expired entries from cache."""
        async with self.lock:
            now = time.time()
            expired_keys = [
                key for key, (_, timestamp) in self.cache.items()
                if now - timestamp >= self.ttl_seconds
            ]

            for key in expired_keys:
                del self.cache[key]

            return len(expired_keys)

# Circuit breaker pattern
class AsyncCircuitBreaker:
    """Async circuit breaker for fault tolerance."""

    def __init__(
        self,
        failure_threshold: int = 5,
        timeout_seconds: float = 60,
        expected_exception: type = Exception
    ):
        self.failure_threshold = failure_threshold
        self.timeout_seconds = timeout_seconds
        self.expected_exception = expected_exception

        self.failure_count = 0
        self.last_failure_time = None
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
        self.lock = asyncio.Lock()

    async def call(self, func, *args, **kwargs):
        """Call function with circuit breaker protection."""
        async with self.lock:
            if self.state == "OPEN":
                if (time.time() - self.last_failure_time) > self.timeout_seconds:
                    self.state = "HALF_OPEN"
                else:
                    raise Exception("Circuit breaker is OPEN")

        try:
            result = await func(*args, **kwargs)

            async with self.lock:
                if self.state == "HALF_OPEN":
                    self.state = "CLOSED"
                self.failure_count = 0

            return result

        except self.expected_exception as e:
            async with self.lock:
                self.failure_count += 1
                self.last_failure_time = time.time()

                if self.failure_count >= self.failure_threshold:
                    self.state = "OPEN"

            raise e

# Example usage of advanced patterns
async def example_advanced_patterns():
    """Example using advanced async patterns."""

    # Rate-limited API calls
    api_resource = RateLimitedResource(max_concurrent=3, rate_limit=5.0)

    async def make_api_call(endpoint: str):
        async with api_resource.acquire():
            # Simulate API call
            await asyncio.sleep(0.1)
            return f"Response from {endpoint}"

    # Cached API calls
    cache = AsyncTTLCache(ttl_seconds=60)

    async def cached_api_call(endpoint: str):
        # Check cache first
        cached_result = await cache.get(endpoint)
        if cached_result:
            return cached_result

        # Make API call if not cached
        result = await make_api_call(endpoint)
        await cache.set(endpoint, result)
        return result

    # Circuit breaker for unreliable service
    circuit_breaker = AsyncCircuitBreaker(failure_threshold=3, timeout_seconds=30)

    async def unreliable_service_call():
        # This might fail occasionally
        if time.time() % 10 < 3:  # Fail 30% of the time
            raise ConnectionError("Service unavailable")
        return "Service response"

    async def protected_service_call():
        try:
            return await circuit_breaker.call(unreliable_service_call)
        except Exception as e:
            return f"Service call failed: {e}"

    # Test the patterns
    tasks = []

    # Multiple concurrent cached API calls
    for i in range(10):
        task = asyncio.create_task(cached_api_call(f"/api/endpoint/{i % 3}"))
        tasks.append(task)

    # Protected service calls
    for i in range(5):
        task = asyncio.create_task(protected_service_call())
        tasks.append(task)

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results
    for i, result in enumerate(results):
        print(f"Task {i}: {result}")

if __name__ == "__main__":
    asyncio.run(example_advanced_patterns())
```

## Part 4: Common Pitfalls and Performance Tips

### Common Async Pitfalls

❌ **DON'T**: Block the event loop with synchronous operations

```python
import asyncio
import time
import requests  # Synchronous HTTP library

# ❌ These block the event loop
async def bad_blocking_examples():
    # Synchronous sleep blocks the entire event loop
    time.sleep(1)  # BAD!

    # Synchronous HTTP requests block
    response = requests.get("https://api.example.com")  # BAD!

    # Heavy CPU computation blocks
    result = sum(i * i for i in range(10_000_000))  # BAD!

    # Synchronous file I/O blocks
    with open("large_file.txt", "r") as f:  # BAD!
        content = f.read()

# ❌ Incorrect async/await usage
async def bad_async_usage():
    # Missing await - this returns a coroutine, doesn't execute it
    asyncio.sleep(1)  # BAD!

    # Using blocking operations in async functions
    time.sleep(1)  # BAD!

    # Not awaiting async functions
    result = some_async_function()  # BAD! Returns coroutine
```

✅ **DO**: Use proper async alternatives

```python
import asyncio
import aiohttp
import aiofiles
from concurrent.futures import ThreadPoolExecutor
import httpx

# ✅ Correct async patterns
async def good_async_examples():
    # Use asyncio.sleep for delays
    await asyncio.sleep(1)  # GOOD!

    # Use async HTTP clients
    async with httpx.AsyncClient() as client:
        response = await client.get("https://api.example.com")  # GOOD!

    # Use async file I/O
    async with aiofiles.open("large_file.txt", "r") as f:  # GOOD!
        content = await f.read()

    # Offload CPU-intensive work to threads
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None,
        lambda: sum(i * i for i in range(10_000_000))  # GOOD!
    )

# ✅ Proper await usage
async def good_async_usage():
    # Always await async functions
    await asyncio.sleep(1)  # GOOD!

    # Properly await async function calls
    result = await some_async_function()  # GOOD!

    # Use async context managers
    async with some_async_context() as resource:  # GOOD!
        await resource.do_something()
```

### Memory and Resource Management

❌ **DON'T**: Create unlimited tasks or ignore resource cleanup

```python
import asyncio

# ❌ Creating unlimited tasks without tracking
async def bad_task_management():
    tasks = []
    for i in range(10000):  # Creates too many tasks!
        task = asyncio.create_task(some_operation(i))
        # Tasks are created but never awaited or cleaned up

    # Memory leak - tasks never cleaned up
    return "Done"

# ❌ Not cleaning up resources
class BadAsyncResource:
    def __init__(self):
        self.connection = None

    async def connect(self):
        self.connection = await create_connection()

    # Missing proper cleanup!
    # Connections will leak when object is garbage collected

# ❌ Ignoring task cancellation
async def bad_cancellation_handling():
    try:
        await asyncio.sleep(10)
    except asyncio.CancelledError:
        pass  # Ignoring cancellation - tasks may not clean up properly
```

✅ **DO**: Properly manage tasks and resources

```python
import asyncio
from contextlib import asynccontextmanager
from typing import Set
import logging

# ✅ Controlled task creation with limits
async def good_task_management():
    semaphore = asyncio.Semaphore(50)  # Limit concurrent tasks

    async def limited_operation(i):
        async with semaphore:
            return await some_operation(i)

    # Create tasks in batches
    tasks = [asyncio.create_task(limited_operation(i)) for i in range(10000)]

    # Process in batches to avoid memory issues
    batch_size = 100
    results = []

    for i in range(0, len(tasks), batch_size):
        batch = tasks[i:i + batch_size]
        batch_results = await asyncio.gather(*batch, return_exceptions=True)
        results.extend(batch_results)

        # Allow other tasks to run
        await asyncio.sleep(0)

    return results

# ✅ Proper resource management
class GoodAsyncResource:
    def __init__(self):
        self.connection = None

    async def __aenter__(self):
        self.connection = await create_connection()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.connection:
            await self.connection.close()
            self.connection = None

    async def connect(self):
        if not self.connection:
            self.connection = await create_connection()

# ✅ Proper cancellation handling
async def good_cancellation_handling():
    cleanup_needed = False
    try:
        cleanup_needed = True
        await asyncio.sleep(10)
        cleanup_needed = False  # Operation completed normally
    except asyncio.CancelledError:
        logging.info("Operation cancelled, cleaning up...")
        if cleanup_needed:
            await cleanup_resources()
        raise  # Re-raise cancellation

# ✅ Task lifecycle management
class TaskLifecycleManager:
    def __init__(self):
        self.active_tasks: Set[asyncio.Task] = set()

    def create_tracked_task(self, coro, *, name: str = None):
        """Create and track a task."""
        task = asyncio.create_task(coro, name=name)
        self.active_tasks.add(task)

        # Remove from tracking when done
        task.add_done_callback(self.active_tasks.discard)
        return task

    async def shutdown(self, timeout: float = 30.0):
        """Gracefully shutdown all tracked tasks."""
        if not self.active_tasks:
            return

        # Cancel all tasks
        for task in self.active_tasks:
            if not task.done():
                task.cancel()

        # Wait with timeout
        try:
            await asyncio.wait_for(
                asyncio.gather(*self.active_tasks, return_exceptions=True),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            logging.warning(f"Tasks didn't complete within {timeout}s")

        self.active_tasks.clear()
```

### Performance Optimization

✅ **DO**: Use appropriate concurrency patterns

```python
import asyncio
import time
from typing import List, Any
import logging

# ✅ Batch processing for better throughput
async def efficient_batch_processing(items: List[Any], batch_size: int = 50):
    """Process items in optimal batches."""

    async def process_batch(batch):
        # Process batch concurrently but with limits
        tasks = [process_single_item(item) for item in batch]
        return await asyncio.gather(*tasks, return_exceptions=True)

    results = []
    for i in range(0, len(items), batch_size):
        batch = items[i:i + batch_size]
        batch_results = await process_batch(batch)
        results.extend(batch_results)

        # Brief pause to allow other tasks
        if i + batch_size < len(items):
            await asyncio.sleep(0)

    return results

# ✅ Connection pooling and reuse
class OptimizedHTTPClient:
    def __init__(self, max_connections: int = 100):
        self.session = None
        self.max_connections = max_connections

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(
            limit=self.max_connections,
            limit_per_host=20,
            keepalive_timeout=30,
            enable_cleanup_closed=True
        )

        timeout = aiohttp.ClientTimeout(
            total=30,
            connect=5,
            sock_read=10
        )

        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def fetch_multiple(self, urls: List[str], max_concurrent: int = 20):
        """Fetch multiple URLs with concurrency control."""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def fetch_one(url):
            async with semaphore:
                try:
                    async with self.session.get(url) as response:
                        return {
                            'url': url,
                            'status': response.status,
                            'data': await response.text()
                        }
                except Exception as e:
                    return {'url': url, 'error': str(e)}

        tasks = [fetch_one(url) for url in urls]
        return await asyncio.gather(*tasks, return_exceptions=True)

# ✅ Efficient async generators
async def optimized_data_stream(data_source):
    """Stream data efficiently with buffering."""
    buffer = []
    buffer_size = 1000

    async for item in data_source:
        buffer.append(await process_item(item))

        if len(buffer) >= buffer_size:
            # Yield batch for processing
            for processed_item in buffer:
                yield processed_item
            buffer.clear()

            # Allow other tasks to run
            await asyncio.sleep(0)

    # Yield remaining items
    for processed_item in buffer:
        yield processed_item

# ✅ Smart caching with async
class AsyncSmartCache:
    def __init__(self, ttl_seconds: int = 300):
        self.cache = {}
        self.ttl_seconds = ttl_seconds
        self.locks = {}
        self.cleanup_task = None

    async def get_or_compute(self, key: str, compute_func):
        """Get from cache or compute with single-flight pattern."""
        now = time.time()

        # Check cache first
        if key in self.cache:
            value, timestamp = self.cache[key]
            if now - timestamp < self.ttl_seconds:
                return value

        # Ensure only one coroutine computes the value
        if key not in self.locks:
            self.locks[key] = asyncio.Lock()

        async with self.locks[key]:
            # Double-check cache after acquiring lock
            if key in self.cache:
                value, timestamp = self.cache[key]
                if now - timestamp < self.ttl_seconds:
                    return value

            # Compute new value
            value = await compute_func()
            self.cache[key] = (value, now)
            return value

    async def start_cleanup(self):
        """Start background cleanup task."""
        if self.cleanup_task is None:
            self.cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def _cleanup_loop(self):
        """Background cleanup of expired entries."""
        while True:
            try:
                await asyncio.sleep(60)  # Cleanup every minute
                now = time.time()
                expired_keys = [
                    key for key, (_, timestamp) in self.cache.items()
                    if now - timestamp >= self.ttl_seconds
                ]

                for key in expired_keys:
                    self.cache.pop(key, None)
                    self.locks.pop(key, None)

                if expired_keys:
                    logging.debug(f"Cleaned up {len(expired_keys)} expired cache entries")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logging.error(f"Cache cleanup error: {e}")
```

### Debugging and Monitoring

✅ **DO**: Add proper logging and monitoring

```python
import asyncio
import logging
import time
from functools import wraps
from typing import Dict, Any
import traceback

# ✅ Async function timing decorator
def async_timed(func):
    """Decorator to time async function execution."""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = await func(*args, **kwargs)
            duration = time.time() - start_time
            logging.info(f"{func.__name__} completed in {duration:.3f}s")
            return result
        except Exception as e:
            duration = time.time() - start_time
            logging.error(f"{func.__name__} failed after {duration:.3f}s: {e}")
            raise
    return wrapper

# ✅ Task monitoring
class AsyncTaskMonitor:
    def __init__(self):
        self.task_stats = {}
        self.active_tasks = set()

    def create_monitored_task(self, coro, *, name: str = None):
        """Create task with monitoring."""
        task_name = name or f"task-{id(coro)}"
        task = asyncio.create_task(coro, name=task_name)

        # Track task
        self.active_tasks.add(task)
        self.task_stats[task_name] = {
            'created': time.time(),
            'status': 'running'
        }

        # Add completion callback
        task.add_done_callback(
            lambda t: self._task_completed(task_name, t)
        )

        return task

    def _task_completed(self, task_name: str, task: asyncio.Task):
        """Handle task completion."""
        self.active_tasks.discard(task)

        if task_name in self.task_stats:
            stats = self.task_stats[task_name]
            stats['completed'] = time.time()
            stats['duration'] = stats['completed'] - stats['created']

            if task.cancelled():
                stats['status'] = 'cancelled'
            elif task.exception():
                stats['status'] = 'failed'
                stats['error'] = str(task.exception())
            else:
                stats['status'] = 'completed'

    def get_stats(self) -> Dict[str, Any]:
        """Get monitoring statistics."""
        return {
            'active_tasks': len(self.active_tasks),
            'completed_tasks': len([
                s for s in self.task_stats.values()
                if s['status'] != 'running'
            ]),
            'task_details': dict(self.task_stats)
        }

# ✅ Async debugging utilities
class AsyncDebugger:
    @staticmethod
    async def slow_callback_detector(threshold: float = 0.1):
        """Detect slow callbacks in event loop."""
        loop = asyncio.get_event_loop()

        def debug_callback():
            start = time.time()

            def check_duration():
                duration = time.time() - start
                if duration > threshold:
                    logging.warning(f"Slow callback detected: {duration:.3f}s")

            loop.call_soon(check_duration)

        # Schedule debug callback periodically
        while True:
            debug_callback()
            await asyncio.sleep(1.0)

    @staticmethod
    def log_task_exceptions():
        """Log unhandled task exceptions."""
        def exception_handler(loop, context):
            exception = context.get('exception')
            if exception:
                logging.error(
                    f"Unhandled task exception: {exception}\n"
                    f"Context: {context}"
                )

                # Log full traceback if available
                if hasattr(exception, '__traceback__'):
                    logging.error(''.join(traceback.format_exception(
                        type(exception), exception, exception.__traceback__
                    )))

        loop = asyncio.get_event_loop()
        loop.set_exception_handler(exception_handler)

# Usage example with monitoring
async def example_with_monitoring():
    """Example showing monitoring and debugging."""

    # Set up monitoring
    monitor = AsyncTaskMonitor()
    AsyncDebugger.log_task_exceptions()

    # Start slow callback detection
    debug_task = asyncio.create_task(
        AsyncDebugger.slow_callback_detector(threshold=0.1)
    )

    try:
        # Create monitored tasks
        tasks = []
        for i in range(10):
            task = monitor.create_monitored_task(
                timed_operation(i),
                name=f"operation-{i}"
            )
            tasks.append(task)

        # Wait for completion
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Print monitoring stats
        stats = monitor.get_stats()
        print(f"Monitoring stats: {stats}")

        return results

    finally:
        debug_task.cancel()
        try:
            await debug_task
        except asyncio.CancelledError:
            pass

@async_timed
async def timed_operation(item_id: int):
    """Example operation with timing."""
    await asyncio.sleep(0.1 + (item_id % 3) * 0.05)  # Variable delay
    if item_id % 7 == 0:  # Simulate occasional failure
        raise ValueError(f"Simulated error for item {item_id}")
    return f"Processed item {item_id}"

if __name__ == "__main__":
    asyncio.run(example_with_monitoring())
```

## References

1. [Python asyncio documentation](https://docs.python.org/3/library/asyncio.html)
2. [Trio async library](https://trio.readthedocs.io/)
3. [AsyncPG documentation](https://magicstack.github.io/asyncpg/current/)
4. [HTTPX documentation](https://www.python-httpx.org/)
5. [SQLAlchemy async support](https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html)
6. [aiohttp documentation](https://docs.aiohttp.org/)
7. [aiofiles documentation](https://github.com/Tinche/aiofiles)
8. [asyncio best practices](https://docs.python.org/3/library/asyncio-dev.html)
9. [Python async/await tutorial](https://realpython.com/async-io-python/)
10. [High Performance Python](https://www.oreilly.com/library/view/high-performance-python/9781492055013/)
