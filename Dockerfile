FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    curl \
    jq \
    python3 \
    python3-pip \
    python3-requests \
    iproute2 \
    iputils-ping \
    net-tools \
    dnsutils \
    nano \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install requests --break-system-packages

CMD ["/bin/bash"]
