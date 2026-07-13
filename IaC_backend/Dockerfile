# 1. Use an official Python runtime as a parent image
FROM python:3.10-slim

# 2. Install system dependencies (git for cloning)
RUN apt-get update && apt-get install -y git curl && rm -rf /var/lib/apt/lists/*

# 3. Install tfsec binary
RUN curl -L -o /usr/local/bin/tfsec https://github.com/aquasecurity/tfsec/releases/latest/download/tfsec-linux-amd64 \
    && chmod +x /usr/local/bin/tfsec

# 4. Set the working directory
WORKDIR /app

# 5. Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 6. Copy the rest of the application code
COPY . .

# 7. Expose the port Flask runs on
EXPOSE 5000

# 8. Run the application
CMD ["python", "run.py"]