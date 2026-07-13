import subprocess
import json
import os

def run_iac_scan(path):
    # The command: tfsec <path> --format json
    # Using check=False because tfsec returns non-zero exit codes if vulnerabilities are found
    try:
        print(f"Running tfsec scan on: {path}")  # Debug log
        result = subprocess.run(
            ["tfsec", path, "--format", "json"],
            capture_output=True,
            text=True,
            check=False 
        )
        
        # If there's output, parse it. Even if exit code is 1, JSON is usually generated.
        if result.stdout:
            print("tfsec output received")  # Debug log
            return json.loads(result.stdout)
        else:
            return {"error": "No output from scanner", "details": result.stderr}
            
    except Exception as e:
        return {"error": f"Scanner execution failed: {str(e)}"}