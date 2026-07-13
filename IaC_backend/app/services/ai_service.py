import os
import requests
from dotenv import load_dotenv

# Load variables from .env
load_dotenv()

SARVAM_API_KEY = os.getenv("SARVAM_API_KEY")
SARVAM_URL = os.getenv("SARVAM_API_URL")

def get_ai_remediation(finding):
    """Fetches remediation from Sarvam AI using official sk_ API keys."""
    
    # Official models include sarvam-105b or sarvam-30b
    # sarvam-105b is recommended for complex coding/security tasks
    payload = {
        "model": "sarvam-105b", 
        "messages": [
            {
                "role": "system", 
                "content": "You are a Cloud Security Expert. Provide 3-step Terraform fixes."
            },
            {
                "role": "user", 
                "content": f"Fix this: {finding['rule_description']}"
            }
        ],
        "temperature": 0.2 # Deterministic for security fixes
    }
    
    # Sarvam uses 'api-subscription-key' header
    headers = {
        "api-subscription-key": SARVAM_API_KEY,
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(SARVAM_URL, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data['choices'][0]['message']['content']
    except Exception as e:
        print(f"AI Error: {e}")
        return "Manual remediation required. Consult CIS benchmarks."