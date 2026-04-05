# Python Base

## Purpose

This component provides the foundational structure for all Python projects in the Claude Code template system. It establishes core Python project patterns, development tools configuration, and essential project files.

## Contents

This directory will contain:

- Basic Python project structure (`src/` layout)
- [`pyproject.toml`](pyproject.toml) configuration with modern Python tooling
- Development environment setup (virtual environment, dependencies)
- Code quality tools configuration (Black, Ruff, isort)
- Type checking setup with mypy
- Pre-commit hooks configuration
- Basic logging and configuration management
- Python packaging structure
- Environment variable management patterns

## Reference

Based on **Section 1.2** of the technical specification - Core Architecture foundation components and **Section 3** for Python development standards including PEP 8 compliance, type hints, and modern tooling integration.

## Usage

This base component is automatically included in all Python-based compositions and can be combined with other components like [`fastapi-base`](../fastapi-base/) or [`pandas-base`](../pandas-base/) depending on project requirements.
