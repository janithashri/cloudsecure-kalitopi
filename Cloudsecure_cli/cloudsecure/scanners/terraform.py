import subprocess
import json
import os
from rich.console import Console

console = Console()

def run_local_scan(scan_path, format='json'):
    # Determine if we are scanning a file or a directory
    if os.path.isfile(scan_path):
        # If it's a file, get the directory it sits in
        exec_path = os.path.dirname(os.path.abspath(scan_path))
    else:
        exec_path = scan_path

    try:
        # We run tfsec on the directory. 
        # --soft-fail ensures it returns JSON even if it finds errors.
        # --include-passed ensures we get the 'Passed' count for your dashboard.
        result = subprocess.run(
            ["tfsec", exec_path, "--format", "json", "--soft-fail", "--include-passed"],
            capture_output=True,
            text=True,
            check=False
        )

        if not result.stdout.strip():
            return {"error": "Scanner returned empty output. Ensure tfsec is installed."}

        # Parse the JSON
        report = json.loads(result.stdout)
        
        # If the user targeted a specific file, we filter the results 
        # to ONLY show issues from that specific file.
        if os.path.isfile(scan_path):
            target_file = os.path.basename(scan_path)
            filtered_results = [
                res for res in report.get("results", []) 
                if os.path.basename(res.get("location", {}).get("filename", "")) == target_file
            ]
            report["results"] = filtered_results

        return report

    except json.JSONDecodeError:
        return {"error": "Failed to parse scanner output. The engine might have crashed."}
    except Exception as e:
        return {"error": str(e)}