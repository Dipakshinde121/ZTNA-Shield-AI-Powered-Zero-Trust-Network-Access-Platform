import sys
import os

# Add WAF-CyberDefense directory to sys.path to allow imports
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "WAF-CyberDefense"))

# Import the Flask app instance from app.py
from app import app
