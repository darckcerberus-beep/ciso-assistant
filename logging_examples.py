"""
Logging Examples - Demonstrates how to use different logging levels in the CISO Assistant.

This script shows practical examples of using DEBUG, INFO, WARNING, ERROR levels
in typical CISO Assistant operations.

Run with:
    python3 logging_examples.py
"""

import logging

from classes import utils

# Configure logging to show DEBUG messages
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

print("\n" + "=" * 80)
print("LOGGING LEVELS DEMONSTRATION")
print("=" * 80 + "\n")

# Example 1: DEBUG level - detailed tracing
print("1. DEBUG Level - Function Entry/Exit and Detailed Traces")
print("-" * 80)
utils.log("Starting user authentication process", level=logging.DEBUG)
utils.log("Validating credentials...", level=logging.DEBUG)
utils.log("Authentication tokens retrieved", level=logging.DEBUG)
print()

# Example 2: INFO level - major operations
print("2. INFO Level - Major Operation Milestones")
print("-" * 80)
utils.log("User authentication completed successfully", level=logging.INFO)
utils.log("Loaded 42 compliance assessments from API", level=logging.INFO)
utils.log("Risk matrix configuration applied successfully", level=logging.INFO)
print()

# Example 3: WARNING level - unexpected but recoverable
print("3. WARNING Level - Unexpected Conditions")
print("-" * 80)
utils.log("Asset 'legacy-database' not found, skipping criticality update", level=logging.WARNING)
utils.log("No perimeter data available for framework 'nist-cst-2.0'", level=logging.WARNING)
utils.log("API rate limit approaching: 45 requests of 50 remaining", level=logging.WARNING)
print()

# Example 4: ERROR level - failures
print("4. ERROR Level - Operation Failures")
print("-" * 80)
utils.log("Failed to update asset criticality: Invalid security objective value", level=logging.ERROR)
utils.log("API error 400 on /api/compliance-assessments/: Invalid framework reference", level=logging.ERROR)
utils.log("Framework configuration file missing: /YML/newDPP.yml", level=logging.ERROR)
print()

# Example 5: CRITICAL level - severe issues
print("5. CRITICAL Level - Critical Failures")
print("-" * 80)
utils.log("API server connection lost and retry exhausted", level=logging.CRITICAL)
utils.log("Database authentication failed with configured credentials", level=logging.CRITICAL)
print()

# Example 6: Practical workflow example
print("6. Practical Workflow Example")
print("-" * 80)

def example_workflow():
    """Example function demonstrating proper logging usage."""
    utils.log("Starting compliance assessment import workflow", level=logging.DEBUG)
    
    try:
        # Simulated operations
        utils.log("Validating input data", level=logging.DEBUG)
        utils.log("Input data validation passed", level=logging.INFO)
        
        utils.log("Creating compliance assessments", level=logging.DEBUG)
        count = 5  # Simulated
        utils.log(f"Successfully created {count} compliance assessments", level=logging.INFO)
        
        utils.log("Assigning requirements to perimeter owners", level=logging.DEBUG)
        utils.log(f"Assigned {count} requirement sets", level=logging.INFO)
        
        utils.log("Workflow completed successfully", level=logging.INFO)
        return True
        
    except (ValueError, KeyError, RuntimeError) as e:
        utils.log(f"Workflow failed: {e}", level=logging.ERROR)
        return False

example_workflow()

print()
print("=" * 80)
print("For more detailed information, see LOGGING_GUIDE.md")
print("=" * 80 + "\n")
