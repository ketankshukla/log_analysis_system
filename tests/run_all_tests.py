"""
Test runner script for the Log Analysis & Monitoring System.
Executes all tests and provides a summary report.
"""
import unittest
import sys
import time
from pathlib import Path

def run_all_tests():
    """Run all tests in the tests directory and display a summary report."""
    start_time = time.time()
    
    # Discover and run all tests
    test_loader = unittest.defaultTestLoader
    test_suite = test_loader.discover(start_dir=Path(__file__).parent, pattern='test_*.py')
    
    # Run the tests
    test_runner = unittest.TextTestRunner(verbosity=2)
    test_result = test_runner.run(test_suite)
    
    # Calculate execution time
    execution_time = time.time() - start_time
    
    # Print summary report
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Tests executed: {test_result.testsRun}")
    print(f"Tests passed: {test_result.testsRun - len(test_result.failures) - len(test_result.errors)}")
    print(f"Tests failed: {len(test_result.failures)}")
    print(f"Test errors: {len(test_result.errors)}")
    print(f"Execution time: {execution_time:.2f} seconds")
    print("=" * 70)
    
    # Return exit code based on test results
    return 0 if test_result.wasSuccessful() else 1

if __name__ == "__main__":
    sys.exit(run_all_tests())
