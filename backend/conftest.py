import sys
import os

# Add the parent directory (workspace root) to sys.path so that
# `from backend.models import ...` and `from backend import parser` work
# when pytest is run from the backend/ directory.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
