# Logging Guide

This guide explains how to use logging effectively throughout the CISO Assistant codebase.

## Overview

The project uses Python's built-in `logging` module to record events during program execution. All logging is centralized in `classes/utils.py` and accessible through the `log()` function.

## Logging Levels

Python defines 5 standard logging levels, from least to most severe:

### DEBUG (Level 10)
**Purpose**: Detailed information for diagnosing problems during development and testing.

**When to use**:
- Function entry/exit traces
- Intermediate computation results
- Detailed variable values
- Low-level operational details

**Examples**:
```python
utils.log(f"Loading configuration from {config_file}", level=logging.DEBUG)
utils.log(f"Processing item {item_id} with value {value}", level=logging.DEBUG)
utils.log("Pagination detected, fetching next page", level=logging.DEBUG)
```

### INFO (Level 20) - Default Level
**Purpose**: Confirmation that things are working as expected (major milestones).

**When to use**:
- Successful completion of significant operations
- Major state changes
- Important business logic execution
- Configuration loading
- Summary statistics

**Examples**:
```python
utils.log(f"Compliance assessment created successfully: {name}", level=logging.INFO)
utils.log(f"Reload completed: {count} compliance assessments loaded", level=logging.INFO)
utils.log(f"Completed fetching all results: {total} items across {pages} pages", level=logging.INFO)
```

### WARNING (Level 30)
**Purpose**: Something unexpected happened or may indicate a potential problem.

**When to use**:
- Recoverable errors or unexpected conditions
- Missing optional resources
- Deprecated feature usage
- Potentially problematic situations that don't stop execution

**Examples**:
```python
utils.log(f"Resource not found (404) on {endpoint}", level=logging.WARNING)
utils.log(f"No {resource_type} found for {criteria}", level=logging.WARNING)
utils.log(f"Retrying operation after connection failure", level=logging.WARNING)
```

### ERROR (Level 40)
**Purpose**: A serious problem that prevented the software from performing a specific function.

**When to use**:
- Operation failures (API calls, file I/O)
- Expected exceptions that are handled
- Data validation failures
- Non-critical failures in batch operations

**Examples**:
```python
utils.log(f"Error 400 on {endpoint}: {response.text}", level=logging.ERROR)
utils.log(f"YAML file not found: {yaml_file}", level=logging.ERROR)
utils.log(f"Failed to create asset: {error_message}", level=logging.ERROR)
```

### CRITICAL (Level 50)
**Purpose**: A very serious error, likely to cause application termination.

**When to use**:
- Critical application failures
- Loss of primary functionality
- System-level errors that prevent recovery
- Configuration errors that prevent startup

**Examples**:
```python
utils.log("API connection failed and cannot be recovered", level=logging.CRITICAL)
utils.log("Database connection lost", level=logging.CRITICAL)
```

## Usage Examples

### Basic Logging
```python
from classes import utils
import logging

# Using default INFO level
utils.log("Operation completed")

# Using specific level
utils.log("Detailed trace information", level=logging.DEBUG)
utils.log("Warning: unusual condition detected", level=logging.WARNING)
utils.log("Error: operation failed", level=logging.ERROR)
```

### In Class Methods
```python
from classes import utils
import logging

class MyClass:
    def __init__(self):
        utils.log("Initializing MyClass", level=logging.DEBUG)
        # ... initialization code ...
        utils.log("MyClass initialized successfully", level=logging.INFO)
    
    def process_item(self, item_id):
        utils.log(f"Processing item: {item_id}", level=logging.DEBUG)
        try:
            result = self._do_processing(item_id)
            utils.log(f"Successfully processed item {item_id}", level=logging.INFO)
            return result
        except Exception as e:
            utils.log(f"Failed to process item {item_id}", level=logging.ERROR)
            raise
    
    def reload_data(self):
        utils.log("Starting data reload", level=logging.DEBUG)
        count = self._load_from_api()
        utils.log(f"Data reload completed: {count} items loaded", level=logging.INFO)
```

## Built-in Utility Function Logging

The utility functions in `classes/utils.py` automatically include logging:

### `load_yaml_file()`
- **DEBUG**: File loading started
- **DEBUG**: File loaded successfully
- **ERROR**: File not found or parsing error

### `get_return()`
- **DEBUG**: API request details (method, endpoint, params)
- **DEBUG**: API response status and endpoint
- **WARNING**: Resource not found (404)
- **ERROR**: Bad request (400) with details
- **ERROR**: Exception during request

### `get_all_results()`
- **INFO**: Started fetching all paginated results
- **DEBUG**: Each page retrieval details
- **DEBUG**: Pagination detection
- **INFO**: Completion summary with total count and page count

## Configuring Logging

The logging is configured in `classes/utils.py`:

```python
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
```

### Changing the Log Level

To see DEBUG messages during development:

```python
import logging

# Set to DEBUG to see all messages
logging.basicConfig(level=logging.DEBUG)
```

To reduce noise in production:

```python
import logging

# Set to WARNING to only see problems
logging.basicConfig(level=logging.WARNING)
```

## Best Practices

1. **Use appropriate levels**: Don't use ERROR for recoverable warnings or DEBUG for major events.

2. **Log at function boundaries**: Log when entering/exiting major functions (DEBUG level) and when they complete (INFO level).

3. **Include context**: Include relevant IDs, counts, or values to make logs meaningful.

4. **Avoid logging sensitive data**: Don't log passwords, tokens, or PII.

5. **Keep messages concise**: Use one message per logical unit.

6. **Use f-strings**: Format messages consistently using f-strings.

## Example Log Output

```
2026-08-29 10:15:30,123 - classes.utils - INFO - Fetching all results from /api/compliance-assessments/
2026-08-29 10:15:30,456 - classes.utils - DEBUG - API request: GET https://localhost:8443/api/compliance-assessments/ with params=None, payload=None
2026-08-29 10:15:30,789 - classes.utils - DEBUG - API response: GET /api/compliance-assessments/ returned status 200
2026-08-29 10:15:30,890 - classes.utils - DEBUG - Page 1: Retrieved 20 results from /api/compliance-assessments/
2026-08-29 10:15:31,123 - classes.audit - INFO - Reload completed: 20 compliance assessments loaded
2026-08-29 10:15:31,234 - classes.audit - INFO - ComplianceAssessmentDict initialized successfully
```

## Related Files

- `classes/utils.py`: Logging implementation and utility functions
- `classes/audit.py`: Example usage in compliance assessment classes
- `classes/organization.py`: Example usage in organization classes
- This guide: `LOGGING_GUIDE.md`
