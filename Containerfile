FROM docker.io/library/python:3.13-alpine
WORKDIR /app
COPY canary.py .
ENV LOG_DIR=/data
CMD ["python3", "-u", "canary.py"]
