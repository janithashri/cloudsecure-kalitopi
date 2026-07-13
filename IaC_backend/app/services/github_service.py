import git
import os
import uuid
from flask import current_app

def clone_repository(repo_url):
    # Generate a unique folder name for this scan
    scan_id = str(uuid.uuid4())
    target_path = os.path.join(current_app.config['SCAN_STORAGE'], scan_id)
    
    try:
        # Shallow clone (depth=1) for speed
        git.Repo.clone_from(repo_url, target_path, depth=1)
        return target_path, scan_id
    except Exception as e:
        raise Exception(f"Cloning failed: {str(e)}")