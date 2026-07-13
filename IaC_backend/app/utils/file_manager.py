import os
import shutil
import stat

def safe_cleanup(directory_path):
    """Deletes a directory even if it contains read-only git files."""
    def handle_errors(func, path, exc_info):
        # Change file to writeable and try again
        os.chmod(path, stat.S_IWRITE)
        func(path)

    if os.path.exists(directory_path):
        shutil.rmtree(directory_path, onerror=handle_errors)