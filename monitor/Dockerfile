FROM python:3.11-slim
RUN apt-get update && apt-get install -y tcpdump libpcap-dev iproute2 gcc \
    && pip install cicflowmeter
CMD ["sleep", "infinity"]
