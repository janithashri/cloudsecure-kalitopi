import os

class Config:
    # Directory where repos will be cloned temporarily
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    SCAN_STORAGE = os.path.join(BASE_DIR, 'temp_scans')
    
    # Ensure the directory exists
    if not os.path.exists(SCAN_STORAGE):
        os.makedirs(SCAN_STORAGE)