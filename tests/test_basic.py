import pytest
import os
import sys

# Adding src to python path for testing
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

def test_imports():
    # A basic test to assert the modules can be imported without syntax errors
    try:
        from src import main
        from src import sa_compromise_response
        from src import storage_exfil_response
        assert True
    except ImportError as e:
        pytest.fail(f"Failed to import modules: {e}")
