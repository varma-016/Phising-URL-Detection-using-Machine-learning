FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

WORKDIR /app

COPY requirements.deploy.txt ./
RUN pip install --no-cache-dir -r requirements.deploy.txt

COPY . .

EXPOSE 8000

CMD ["sh", "-c", "uvicorn api_simple:app --host 0.0.0.0 --port ${PORT}"]
