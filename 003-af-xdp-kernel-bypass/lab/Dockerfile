FROM debian:12-slim

COPY lab/data/*.conf /etc/wireguard/

RUN DEBIAN_FRONTEND=noninteractive apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get -q -y --no-install-recommends install \
        curl \
        hping3 \
        inetutils-ping \
        iproute2 \
        iptables \
        procps \
        tcpdump \
        vim \
        wireguard \
        wireguard-tools \
