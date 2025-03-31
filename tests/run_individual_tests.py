"""
Script to run individual test modules to identify which ones are passing and which are failing.
"""
import unittest
import sys
import importlib
import traceback

def run_test_module(module_name):
    """Run a specific test module and report results."""
    print(f"\n{'=' * 70}")
    print(f"RUNNING TEST MODULE: {module_name}")
    print(f"{'=' * 70}")
    
    try:
        # Try to import the module
        module = importlib.import_module(f"tests.{module_name}")
        
        # Run the tests in the module
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromModule(module)
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        
        # Report results
        print(f"\nResults for {module_name}:")
        print(f"Tests run: {result.testsRun}")
        print(f"Errors: {len(result.errors)}")
        print(f"Failures: {len(result.failures)}")
        
        return len(result.errors) == 0 and len(result.failures) == 0
        
    except Exception as e:
        print(f"\nFailed to run {module_name}:")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    # List of test modules to run
    test_modules = [
        "test_parsers",
        "test_analyzers",
        "test_helpers",
        "test_storage",
        "test_alerting"
    ]
    
    # Run each module and collect results
    results = {}
    
    for module in test_modules:
        results[module] = run_test_module(module)
    
    # Print summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    all_passed = True
    for module, passed in results.items():
        status = "PASSED" if passed else "FAILED"
        print(f"{module}: {status}")
        all_passed = all_passed and passed
    
    # Set exit code
    sys.exit(0 if all_passed else 1)
