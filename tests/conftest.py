import sys
import os

# Add python/ directory to path so tests can import modules, bfd, lldp packages
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
