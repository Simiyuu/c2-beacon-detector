FROM python:3.11-slim

# Prevent Python from buffering stdout/stderr and avoid writing .pyc files
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Cache and install Python dependencies from wheels
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source and sample data
COPY src/ ./src/
COPY sample_data/ ./sample_data/

# Run as non-privileged service user
RUN useradd -u 10001 -m appuser && \
    chown -R appuser:appuser /app
USER appuser

ENTRYPOINT ["python", "-m", "src.cli"]
CMD ["--help"]