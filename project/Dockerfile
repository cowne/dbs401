FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY . .
COPY ./certs /app/certs

RUN pip install mysql-connector-python sqlparse flask

# Expose port
EXPOSE 80

CMD [ "./start.sh" ]
# CMD [ "python","proxy.py" ]
