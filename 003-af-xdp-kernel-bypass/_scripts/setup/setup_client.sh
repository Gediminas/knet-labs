#!/usr/bin/env bash

set -euo pipefail
[[ -n "${DEBUG:-}" ]] && set -x

SECONDS=0  # Reset the SECONDS variable

#####################################
cat <<EOF
-------------------------------------------------------------------------
* Client
--------
KERNEL: $(uname -r)
USER: $(whoami)
------------------------
EOF
#####################################

# default via 192.168.121.1 dev eth0
# 10.5.0.0/16 dev wg0 proto kernel scope link src 10.5.0.2
# 192.168.56.0/24 dev eth1 proto kernel scope link src 192.168.56.101
# 192.168.121.0/24 dev eth0 proto kernel scope link src 192.168.121.149

# wg-quick down wg0 || true
# ip route del default || true
# ip route add default via 192.168.56.100 || true
# rm -rf /etc/wireguard/wg0.conf


export DEBIAN_FRONTEND=noninteractive

apt-get -y -q --no-install-recommends install \
    wireguard \
    wireguard-tools \
    tcpdump \
    curl \
    vim \
    hping3 \
    > /dev/null

# FIXME
wg-quick down wg0 || true
rm -rf /etc/wireguard/wg0.conf

if [[ ! -f /etc/wireguard/wg0.conf ]] ; then
    echo ------------------------
    echo "Adding Client Wireguard config wg0"

    cat << EOF > /etc/wireguard/wg0.conf
[Interface]
  ListenPort = 51820
  Address = 10.5.0.2/16
  PrivateKey = CD2dqWTG5PltmCZdT0KfbaJdArriOndMibTw2/CLK2w=
        #pub = C6qtaptmuYQLUM5z0FXjR3ECBL85I1eYeMBlcbu5BDY=

[Peer]
  PublicKey = csmoelQgK1QvyE5+XmZnXaPNt/zCgk84BG6BwfcmOFE=
      #priv = cOmmSJBi5IJ2Uh1AZsNZjmnEiGsr4MHpNUlAi1xUrmE=
  AllowedIPs = 0.0.0.0/0
  Endpoint = 192.168.211.100:51820
EOF

    wg-quick up wg0
fi

# sudo ip route del default || true
# sudo ip route add default via 10.5.0.1
# sudo ip route add default via 10.5.0.1

# echo "* Curl example.com once"
# curl -s example.com > /dev/null

ping 10.5.0.1 -c 3

sudo ip route del 0.0.0.0/0 via 10.5.0.1 metric 1 || true
sudo ip route add 0.0.0.0/0 via 10.5.0.1 metric 1


echo "GREAT SUCCESS!!! Setup took ${SECONDS}s"
