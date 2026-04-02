# Documentation Standards

## General Principles
- Keep documentation close to the code
- Update documentation with code changes
- Use clear, concise language
- Include examples where helpful
- Follow patterns in existing documentation

## README Requirements
Every project must have a README.md with:
- **Project Title and Description**: Clear explanation of purpose
- **Prerequisites**: Required tools, versions, and dependencies
- **Installation**: Step-by-step setup instructions
- **Configuration**: Environment variables and config files
- **Usage**: Basic usage examples and common workflows
- **Development Setup**: How to set up development environment
- **Testing**: How to run tests and interpret results
- **Deployment**: Deployment process and considerations
- **Architecture**: High-level architecture overview (link to detailed docs)
- **Contributing**: Guidelines for contributors
- **License**: License information
- **Support**: How to get help or report issues

## Code Documentation

### Python
- Use docstrings for all public modules, classes, and functions
- Follow Google Style Python docstring style consistently
- Include type hints in function signatures
- Document parameters, return values, and exceptions
- Include usage examples for complex functions

```python
def process_data(input_data: list[dict], validate: bool = True) -> dict:
    """Process input data and return aggregated results.

    Args:
        input_data: List of dictionaries containing raw data
        validate: Whether to validate input data before processing

    Returns:
        Dictionary containing processed and aggregated results

    Raises:
        ValueError: If input_data is empty or invalid

    Example:
        >>> data = [{"value": 1}, {"value": 2}]
        >>> result = process_data(data)
        >>> print(result["total"])
        3
    """
```

### TypeScript
- Use JSDoc comments for all public functions and classes
- Include type information in JSDoc
- Document parameters, return values, and exceptions
- Include usage examples for complex functions

```typescript
/**
 * Process user data and return formatted result
 *
 * @param userData - Raw user data from API
 * @param options - Processing options
 * @returns Formatted user object
 * @throws {ValidationError} If userData is invalid
 *
 * @example
 * ```ts
 * const user = processUserData(rawData, { validate: true });
 * console.log(user.name);
 * ```
 */
function processUserData(userData: RawUser, options: ProcessOptions): User {
    // Implementation
}
```

### Shell Scripts
- Add description at the top of the script
- Document usage and examples
- Comment complex logic
- Document function parameters

## API Documentation
- Use OpenAPI/Swagger for REST APIs
- Document all endpoints, parameters, and responses
- Include example requests and responses
- Document error codes and meanings
- Document authentication requirements
- Keep API docs versioned with the API
- Include rate limiting information
- Document deprecation notices

## Architecture Documentation

### Architecture Decision Records (ADRs)
- Document significant architectural decisions
- Use consistent ADR template
- Store in `docs/adr/` directory
- Include: context, decision, consequences, alternatives considered

### System Architecture
- Maintain architecture diagrams (C4 model recommended)
- Document system components and interactions
- Explain design patterns used
- Document integration points and APIs
- Keep diagrams up-to-date with code changes
- Use tools like Mermaid, PlantUML, or draw.io

### Infrastructure Documentation
- Document infrastructure architecture
- Include network diagrams
- Document deployment procedures
- Explain disaster recovery procedures
- Document monitoring and alerting setup

## Documentation in `docs/` Directory
- Organize documentation logically by topic
- Use consistent file naming conventions
- Create index/table of contents for navigation
- Include getting started guide
- Document common troubleshooting issues
- Keep documentation versioned with code
- Use markdown for text documentation
- Store diagrams as code when possible (Mermaid, PlantUML)

## Inline Comments
- Comment the "why", not the "what"
- Explain complex algorithms or business logic
- Document assumptions and limitations
- Mark TODOs with issue references
- Keep comments up-to-date with code
- Remove commented-out code (use version control)

## Changelog
- Maintain CHANGELOG.md following Keep a Changelog format
- Document all notable changes
- Group changes by type (Added, Changed, Deprecated, Removed, Fixed, Security)
- Include version numbers and dates
- Link to relevant issues/PRs

## Security Documentation
- Document security considerations
- Explain authentication and authorization
- Document secrets management approach
- Include security contact information
- Document known security limitations
