FROM python:3.10-slim

WORKDIR /app

COPY . .
COPY ./certs /app/certs

RUN pip install mysql-connector-python sqlparse

CMD ["python", "proxy.py"]
