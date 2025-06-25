FROM python:3.11-slim

WORKDIR /app

COPY . .
COPY ./certs /app/certs

RUN pip install --no-cache-dir -r requirements.txt

# Expose the proxy API port
EXPOSE 8000

CMD ["uvicorn", "proxy_server:app", "--host", "0.0.0.0", "--port", "8000"]
