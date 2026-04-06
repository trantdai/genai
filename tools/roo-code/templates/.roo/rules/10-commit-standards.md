# Commit Message Standards

## Conventional Commit Format
Use conventional commit message format for all commits.

## Structure
```
<type>(<scope>): <icon> <short description>

<longer description (optional)>

<footer (optional)>
```

## Format Requirements
- **Short description**: 50 characters or less
- **Blank line**: Required between short and long description
- **Long description**: Wrap at 72 characters, explain what and why
- **Footer**: Reference issues, breaking changes, etc.

## Type Categories
- `feat`: ✨ New feature for the user
- `fix`: 🐛 Bug fix for the user
- `docs`: 📚 Documentation changes
- `style`: 💄 Code style changes (formatting, missing semi colons, etc)
- `refactor`: ♻️ Code change that neither fixes a bug nor adds a feature
- `test`: 🧪 Adding missing tests or correcting existing tests
- `chore`: 🔧 Changes to the build process or auxiliary tools
- `perf`: ⚡ Performance improvements
- `ci`: 👷 Changes to CI configuration files and scripts
- `build`: 📦 Changes that affect the build system or external dependencies
- `revert`: ⏪ Reverts a previous commit
- `wip`: 🚧 Work in progress (avoid in main branch)
- `security`: 🔒 Security improvements or fixes
- `config`: ⚙️ Configuration changes
- `deps`: ⬆️ Dependency updates
- `infra`: 🏗️ Infrastructure changes
- `typo`: ✏️ Fixing typos
- `comment`: 💬 Adding or updating comments
- `example`: 📝 Adding or updating examples
- `mock`: 🎭 Adding or updating mocks
- `hotfix`: 🚑 Critical hotfix
- `cleanup`: 🧹 Code cleanup
- `optimize`: 🚀 Code optimization

## Scope Guidelines
- Use lowercase
- Keep short and descriptive
- Examples: `api`, `ui`, `auth`, `db`, `config`, `tests`, `docs`
- Use component or module names where applicable

## Examples

### Good Commit Messages
```
feat(auth): ✨ add OAuth2 integration with Google

Implement Google OAuth2 authentication flow including:
- OAuth2 client configuration
- User profile retrieval
- Token refresh mechanism

Closes #123
```

```
fix(api): 🐛 handle null values in user profile endpoint

The endpoint was throwing 500 errors when user profile
contained null values for optional fields.

Fixes #456
```

```
docs(readme): 📚 update installation instructions

Add Docker setup instructions and troubleshooting section
for common installation issues.
```

```
security(auth): 🔒 implement rate limiting for login attempts

Add rate limiting to prevent brute force attacks:
- 5 attempts per minute per IP
- Exponential backoff on failures
- Proper logging of failed attempts
```

### Avoid These Patterns
❌ `fix bug`
❌ `update code`
❌ `WIP`
❌ `fixed the thing`
❌ `misc changes`

## Breaking Changes
For breaking changes, add `BREAKING CHANGE:` in the footer:

```
feat(api): ✨ redesign user authentication API

BREAKING CHANGE: The authentication endpoint now requires
a different request format. See migration guide in docs/
```

## Multi-line Descriptions
When needed, provide context in the longer description:

```
refactor(database): ♻️ optimize user query performance

Restructured user queries to reduce database load:
- Added proper indexing on frequently queried fields
- Implemented query result caching
- Reduced N+1 query problems in user relationships

Performance improvement: 60% faster average response time
```

## Revert Commits
```
revert: ⏪ feat(auth): add OAuth2 integration

This reverts commit 667ecc1654a317a13331b17617d973392f415f02.

Reason: OAuth2 integration causing login failures in production
```

## Tools Integration
- Use `commitizen` or `conventional-changelog` tools for automated formatting
- Configure git hooks to validate commit message format
- Use `semantic-release` for automated versioning based on commit types

## Best Practices
- Write commits in imperative mood ("add feature" not "added feature")
- Be specific about what changed and why
- Reference related issues and PRs
- Keep commits atomic (one logical change per commit)
- Use the body to explain context and reasoning
- Use the footer for metadata (issue references, breaking changes)
