FROM python:3.12-slim

# Prevent Python from writing bytecode and enable unbuffered terminal logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies using layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy engine modules, benchmark harness, and documentation
COPY src/ ./src/
COPY evaluate.py ./evaluate.py
COPY README.md ./README.md

# Non-root unprivileged service user
RUN useradd -u 10001 -m appuser && \
    chown -R appuser:appuser /app

USER appuser

ENTRYPOINT ["python", "-m", "src.cli"]
CMD ["--help"]
