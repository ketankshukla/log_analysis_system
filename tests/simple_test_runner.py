"""
Simple test runner to run tests one at a time and identify specific failures.
This runner will import each test class individually and run it to isolate issues.
"""
import unittest
import sys
import importlib
import traceback

def run_test_class(module_name, class_name):
    """Run a specific test class and report results."""
    print(f"\n{'=' * 70}")
    print(f"RUNNING TEST CLASS: {module_name}.{class_name}")
    print(f"{'=' * 70}")
    
    try:
        # Try to import the module
        module = importlib.import_module(f"tests.{module_name}")
        
        # Get the test class
        test_class = getattr(module, class_name)
        
        # Run the tests
        suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        
        # Report results
        print(f"\nResults for {module_name}.{class_name}:")
        print(f"Tests run: {result.testsRun}")
        print(f"Errors: {len(result.errors)}")
        print(f"Failures: {len(result.failures)}")
        
        for error in result.errors:
            print(f"\nERROR: {error[0]}")
            print(error[1])
        
        for failure in result.failures:
            print(f"\nFAILURE: {failure[0]}")
            print(failure[1])
        
        return len(result.errors) == 0 and len(result.failures) == 0
        
    except Exception as e:
        print(f"\nFailed to run {module_name}.{class_name}:")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    # Test classes to run
    test_classes = [
        ("test_parsers", "TestApacheLogParser"),
        ("test_helpers", "TestHelperFunctions"),
        ("test_storage", "TestLogDatabase"),
        ("test_alerting", "TestAnomalyDetector"),
        ("test_alerting", "TestEmailNotifier")
    ]
    
    # Run each test class and collect results
    results = {}
    
    for module, class_name in test_classes:
        key = f"{module}.{class_name}"
        results[key] = run_test_class(module, class_name)
    
    # Print summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    all_passed = True
    for test_key, passed in results.items():
        status = "PASSED" if passed else "FAILED"
        print(f"{test_key}: {status}")
        all_passed = all_passed and passed
    
    # Set exit code
    sys.exit(0 if all_passed else 1)
