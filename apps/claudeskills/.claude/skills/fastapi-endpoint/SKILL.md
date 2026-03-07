---
name: fastapi-endpoint
description: Create a new FastAPI endpoint for the claudeskills REST API
argument-hint: [resource-name] [http-method]
disable-model-invocation: true
---

Create a FastAPI **$1** endpoint for the **$0** resource.

## Project Context
- Project: claudeskills (FastAPI + Temporal showcase)
- API location: `claudeskills/api/`
- Follow patterns from `claudeskills/api/main.py`

## Generate These Files

### 1. Router: `claudeskills/api/routes/$0.py`
```python
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status

from claudeskills.api.schemas.$0 import ${0}Create, ${0}Response, ${0}List
from claudeskills.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/$0", tags=["$0"])


@router.$1("/{id}" if "$1" in ["get", "put", "delete"] else "")
async def ${1}_$0(
    # Add parameters here
) -> ${0}Response:
    """$1 $0."""
    logger.info("${1}_$0_called")

    try:
        # Your endpoint logic here
        pass

    except Exception as e:
        logger.error("${1}_$0_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
```

### 2. Schemas: `claudeskills/api/schemas/$0.py`
```python
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional


class ${0}Base(BaseModel):
    """Base schema for $0."""
    # Add your common fields
    pass


class ${0}Create(${0}Base):
    """Schema for creating $0."""
    # Add fields required for creation
    pass


class ${0}Response(${0}Base):
    """Schema for $0 response."""
    id: str = Field(..., description="Unique identifier")
    created_at: datetime = Field(..., description="Creation timestamp")

    class Config:
        json_schema_extra = {
            "example": {
                "id": "123",
                "created_at": "2024-01-01T00:00:00Z"
            }
        }


class ${0}List(BaseModel):
    """Schema for list of $0s."""
    items: list[${0}Response]
    total: int
    page: int = 1
    page_size: int = 10
```

### 3. Tests: `tests/api/test_$0.py`
```python
from fastapi.testclient import TestClient
import pytest


def test_${1}_$0_success(client: TestClient) -> None:
    """Test $1 $0 returns successfully."""
    # Arrange
    # Act
    response = client.$1("/$0")

    # Assert
    assert response.status_code == 200


def test_${1}_$0_validation_error(client: TestClient) -> None:
    """Test $1 $0 handles validation errors."""
    # Test invalid input
    pass


def test_${1}_$0_not_found(client: TestClient) -> None:
    """Test $1 $0 handles not found case."""
    # Test 404 scenario
    pass
```

### 4. Register Router: `claudeskills/api/main.py`

Add import and registration:
```python
from claudeskills.api.routes import $0

# In create_app(), add:
app.include_router($0.router, prefix="/api", tags=["$0"])
```

## Requirements
- Use proper HTTP status codes
- Add OpenAPI documentation
- Include request/response examples
- Validate inputs with Pydantic
- Handle errors gracefully
- Write comprehensive tests

## After Creating

### 1. Setup Virtual Environment (if not already done)
```bash
cd /Users/dai.tran/Developer/personal/genai/apps/claudeskills
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
```

### 2. Run Tests
```bash
source .venv/bin/activate  # Ensure venv is activated
pytest tests/api/test_$0.py -v
```

### 3. Test the API
- Check API docs: Visit http://localhost:8000/docs
- Test manually: `curl http://localhost:8000/api/$0`
