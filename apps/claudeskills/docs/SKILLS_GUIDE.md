# How to Use Claude Code Skills to Build This Application

## 🎯 Learning Approach

Instead of having Claude build everything for you, **use skills to learn and build iteratively**. Each skill is a template that teaches you patterns while helping you create code.

## 📋 Available Skills

Run these commands to invoke skills:

| Skill | Command | Purpose |
|-------|---------|---------|
| **temporal-workflow** | `/temporal-workflow <name> <description>` | Create new workflow with activities |
| **fastapi-endpoint** | `/fastapi-endpoint <resource> <method>` | Create new REST API endpoint |
| **add-tests** | `/add-tests <file-path>` | Generate tests for existing code |
| **review-code** | `/review-code <file-or-dir>` | Review code for issues and improvements |

## 🚀 Building Phase 2: Workflow Example

Let's walk through implementing the first workflow feature from the PRD (REQ-WF-001: Long-running data processing workflow).

### Step 1: Create Your First Workflow

```text
/temporal-workflow DataProcessing process data through validation, transformation, and storage steps
```

**What happens:**
- Claude generates workflow, activities, and tests
- You review the generated code
- You learn Temporal patterns (activities, retries, timeouts)

### Step 2: Create the API Endpoint

```text
/fastapi-endpoint workflows post
```

**What happens:**
- Claude generates FastAPI router with schemas
- Creates POST endpoint to start workflows
- You see REST API patterns and Pydantic validation

### Step 3: Connect API to Workflow

**Manual step - this is where YOU learn:**

After Claude generates the code, YOU need to:

1. Review the generated endpoint
2. Add Temporal client connection
3. Start the workflow from the API
4. Return workflow ID to caller

**Ask Claude for help:**
```text
How do I connect the /api/workflows POST endpoint to start a DataProcessing workflow in Temporal?
```

Claude will explain the integration and show you code examples.

### Step 4: Add Tests

```text
/add-tests claudeskills/workflows/data_processing_workflow.py
```

**What happens:**
- Claude generates comprehensive tests
- You learn testing patterns for Temporal
- See how to mock activities and test workflows

### Step 5: Review Your Code

```text
/review-code claudeskills/workflows/
```

**What happens:**
- Claude reviews for best practices
- Identifies issues (determinism, error handling)
- Suggests improvements
- You learn what good Temporal code looks like

## 📚 Iterative Learning Workflow

### Pattern 1: Feature Development
```
1. /temporal-workflow <name> <description>    # Generate structure
2. Review and understand the code             # Learn the patterns
3. Customize the generated code               # Apply to your needs
4. /add-tests <file>                          # Ensure quality
5. /review-code <file>                        # Get feedback
6. Iterate based on review                    # Improve
```

### Pattern 2: API First
```
1. /fastapi-endpoint <resource> <method>      # Create endpoint
2. Design the request/response schemas        # Define contract
3. /temporal-workflow <name> <description>    # Create backend
4. Connect API → Temporal                     # Integration
5. /add-tests for both API and workflow       # Test everything
```

### Pattern 3: Test-Driven Development
```
1. Ask: "What tests should I write for a data processing workflow?"
2. Write tests first (or have Claude help)
3. /temporal-workflow to generate implementation
4. Run tests, iterate until passing
5. /review-code to ensure quality
```

## 💡 Example Conversation Flow

**You:** "I need to implement REQ-API-001 from the PRD - workflow management endpoints"

**Claude:** "Let's break this down into the required endpoints. Start with POST /workflows to create workflows. Use: `/fastapi-endpoint workflows post`"

**You:** `/fastapi-endpoint workflows post`

**Claude:** [Generates code]

**You:** "Now I need this to actually start a Temporal workflow. How do I do that?"

**Claude:** [Explains Temporal client usage, shows integration code]

**You:** [Reviews, modifies, commits code]

**You:** `/review-code claudeskills/api/routes/workflows.py`

**Claude:** [Reviews code, suggests improvements]

**You:** [Makes improvements based on feedback]

## 🔄 Building REQ-WF-001: Data Processing Workflow

Let's implement the first workflow requirement from the PRD step-by-step:

### Phase A: Understanding (Ask Questions)

```text
Can you explain what a "long-running data processing workflow" should do in Temporal? What activities would it need?
```

### Phase B: Create Structure

```text
/temporal-workflow DataProcessing validate input data, transform it through multiple steps, store results, and send completion notification
```

### Phase C: Review Generated Code

- Open `claudeskills/workflows/data_processing_workflow.py`
- Understand the structure
- Ask questions: "Why is the retry policy set to 3 attempts?"

### Phase D: Customize Activities

```text
I need to add three activities to the DataProcessing workflow:
1. validate_data - checks data format and schema
2. transform_data - applies business rules
3. store_results - saves to database

Can you update the activities file with proper implementations?
```

### Phase E: Add Tests

```text
/add-tests claudeskills/workflows/data_processing_workflow.py
```

### Phase F: Integration with API

```text
/fastapi-endpoint workflows post

After this generates, help me modify it to:
1. Accept workflow input parameters
2. Connect to Temporal client
3. Start DataProcessing workflow
4. Return workflow ID and status
```

### Phase G: End-to-End Test

```text
/add-tests claudeskills/api/routes/workflows.py

Then help me create an integration test that:
1. Calls POST /api/workflows
2. Waits for workflow completion
3. Verifies the result
```

### Phase H: Quality Check

```text
/review-code claudeskills/workflows/
/review-code claudeskills/api/routes/workflows.py
```

## 🎓 Learning Outcomes

By using skills this way, you:

1. **Learn patterns** - See how to structure Temporal workflows properly
2. **Understand integration** - Connect FastAPI ↔ Temporal
3. **Practice testing** - Write unit and integration tests
4. **Get feedback** - Code reviews teach best practices
5. **Build incrementally** - Small, testable pieces
6. **Stay in control** - YOU decide what gets built and how

## 📝 Next Steps

1. **Install dependencies:**
   ```bash
   make install-dev
   ```

2. **Start Temporal:**
   ```bash
   make docker-up
   ```

3. **Build your first feature:**
   ```text
   /temporal-workflow DataProcessing handle data validation, transformation, and storage
   ```

4. **Keep iterating with skills as you implement the PRD requirements!**

## 💬 Getting Help

Ask questions like:
- "What should a Temporal activity look like for calling an external API?"
- "How do I handle errors in workflows?"
- "What's the best way to test long-running workflows?"
- "Show me an example of the Saga pattern for distributed transactions"

Use `/review-code` frequently to get feedback and learn best practices!
