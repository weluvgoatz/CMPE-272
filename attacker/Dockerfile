FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y \
    nmap \
    hping3 \
    hydra \
    slowhttptest \
    python3 python3-pip \
    iputils-ping \
    && pip3 install --break-system-packages requests
CMD ["sleep", "infinity"]
