FROM python:3.11-slim

WORKDIR /app

# Prevents Python from writing .pyc files and buffers stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source
COPY . .

EXPOSE 8000

# Use uvicorn with bind to all interfaces for container
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

