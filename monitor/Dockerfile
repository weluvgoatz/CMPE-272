FROM python:3.11-slim
RUN apt-get update && apt-get install -y tcpdump libpcap-dev iproute2 gcc tcpreplay \
    && pip install cicflowmeter scapy numpy scipy requests pandas \
    && pip install pyflowmeter --no-deps
CMD ["sleep", "infinity"]
