# TypeScript Development Standards

## Project Architecture
- Study and follow patterns established in `docs/` directory for consistency
- Organize by feature, not by file type
- Use barrel exports (index.ts) for clean imports
- Keep components/modules small and focused
- Separate types into dedicated `.types.ts` files when complex

## Code Style & Security
- Use ESLint with TypeScript-specific rules and security plugins
- Use Prettier for code formatting
- Strict TypeScript configuration (`strict: true` in tsconfig.json)
- No `any` types unless absolutely necessary (document why)
- Use explicit return types for functions

## Secure Coding Practices
- **Input Validation**: Validate all user inputs using libraries like Zod, Joi, or Yup
- **XSS Prevention**: Use proper output encoding and CSP headers
- **CSRF Protection**: Implement CSRF tokens for state-changing operations
- **Authentication**: Use secure JWT handling with proper expiration
- **Secrets Management**: Never hardcode secrets, use environment variables
- **Dependency Security**: Regular updates and vulnerability scanning
- **Error Handling**: Sanitize error messages before sending to client
- **SQL Injection Prevention**: Use parameterized queries or ORMs
- **Path Traversal Prevention**: Validate file paths and user inputs

## Type Safety
- Prefer interfaces over types for object shapes
- Use discriminated unions for complex state management
- Leverage utility types (Partial, Pick, Omit, Record, etc.)
- Use const assertions where appropriate
- Enable `strictNullChecks` and handle null/undefined explicitly
- Use branded types for domain-specific values

## Testing
- Use Jest or Vitest for unit testing
- Use Testing Library for component testing
- Minimum 80% code coverage
- Mock external dependencies properly
- Test error cases, edge conditions, and security boundaries
- Use snapshot testing judiciously

## Async Operations
- Use async/await over raw Promises
- Handle errors with try/catch blocks
- Use Promise.all() for concurrent operations
- Implement proper timeout handling for external calls
- Use AbortController for cancellable requests

## Dependencies
- Specify minimum version constraints (e.g., `>=1.2.0`)
- Regularly update dependencies for security patches
- Avoid deprecated packages
- Document why specific versions are pinned
