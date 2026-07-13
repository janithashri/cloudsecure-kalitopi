# 🛡️ CloudSecure CLI 
> **Intelligent Auditing for Modern Infrastructure [Kaali Topi]**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Team: Kaali Topi](https://img.shields.io/badge/Team-Kaali%20Topi-magenta)](https://github.com/your-org/cloudsecure)

**CloudSecure** is a professional-grade Infrastructure as Code (IaC) security scanner. It allows developers to perform deep ingestion of Terraform files locally to identify security gaps, leaked secrets, and misconfigurations before they are deployed to the cloud.

---

## 🛠️ Installation Guide

Follow these steps to get the **CloudSecure CLI** running on your local machine.

### 1. Install the Scanning Engine
CloudSecure uses **tfsec** as its primary analysis engine. You must have it installed in your system path:
* **MacOS:** `brew install tfsec`
* **Linux:** `curl -s https://raw.githubusercontent.com/aquasecurity/tfsec/master/scripts/install.sh | bash`
* **Windows:** `choco install tfsec`

### 2. Install the CLI Package
You can install the tool directly from the internet or from your local source folder.

**Option A: From PyPI**
```bash
pip install cloudsecure-kaalitopi