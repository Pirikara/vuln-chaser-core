#!/usr/bin/env python3
"""
VulnChaser Core Server Startup Script
"""
import os
import sys
import uvicorn
from pathlib import Path

# Add the current directory to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

def main():
    # Check for required environment variables
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        print("ERROR: OPENROUTER_API_KEY environment variable is required")
        sys.exit(1)
    
    # Server configuration
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    log_level = os.getenv("LOG_LEVEL", "info").lower()
    
    print(f"Starting VulnChaser Core Server...")
    print(f"Host: {host}")
    print(f"Port: {port}")
    print(f"Model: {os.getenv('OPENROUTER_MODEL', 'google/gemma-3-27b-it:free')}")
    print(f"Log Level: {log_level}")
    
    # Start the server
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=True,
        log_level=log_level,
        access_log=True
    )

if __name__ == "__main__":
    main()