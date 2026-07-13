# Pin amd64 after moving Docker disk image (avoids exec format error on wrong arch layers)
FROM --platform=linux/amd64 python:3.11-slim

# Default: requirements-core.txt (API + inventory). Deep-scan service sets REQUIREMENTS_FILE=requirements-deep.txt
ARG REQUIREMENTS_FILE=requirements-core.txt

ENV PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements-core.txt requirements-deep.txt requirements-anomaly.txt ./
RUN pip install --no-cache-dir -r ${REQUIREMENTS_FILE} \
    && pip install --no-cache-dir -r requirements-anomaly.txt
COPY . .

ENV PYTHONPATH=/app

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
