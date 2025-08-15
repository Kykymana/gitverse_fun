# deployment-manager/backend/Dockerfile
FROM python:3.9-slim-bullseye

WORKDIR /app

# Установка git, чтобы команды git log/clone работали
RUN apt-get update && apt-get install -y git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

COPY ssh_keys/ /app/ssh_keys/
RUN chmod 600 /app/ssh_keys/server_key && chmod 600 /app/ssh_keys/repo_key
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]