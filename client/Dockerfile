FROM python:3.11-slim
RUN apt-get update && apt-get install -y curl openssh-client ftp iputils-ping \
    && pip install requests
COPY benign_traffic.py /app/benign_traffic.py
CMD ["python", "/app/benign_traffic.py"]
