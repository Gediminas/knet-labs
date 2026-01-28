#!/usr/bin/env bash
# 
set -euo pipefail
[[ -n "${DEBUG:-}" ]] && set -x

SECONDS=0  # Reset the SECONDS variable

#####################################
cat <<EOF
-------------------------------------------------------------------------
* Server
--------
KERNEL: $(uname -r)
USER: $(whoami)
------------------------
EOF
#####################################

export DEBIAN_FRONTEND=noninteractive

apt-get -y -q --no-install-recommends install \
    wireguard \
    wireguard-tools \
    tcpdump \
    curl \
    vim \
    > /dev/null

sysctl -w net.ipv4.ip_forward=1

# FIXME
wg-quick down wg0 || true
rm -rf /etc/wireguard/wg0.conf

if [[ ! -f /etc/wireguard/wg0.conf ]] ; then
    echo  --------
    echo "Adding Server Wireguard config wg0"

    # [Interface]
    # Address = 10.5.0.1/16
    # Address = fd00::1/112
    # ListenPort = 51820
    # PrivateKey = cOmmSJBi5IJ2Uh1AZsNZjmnEiGsr4MHpNUlAi1xUrmE=
    # PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    # PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

    cat << EOF > /etc/wireguard/wg0.conf
[Interface]
  ListenPort = 51820
  Address = 10.5.0.1/16
  Address = fd00::1/112
  PrivateKey = cOmmSJBi5IJ2Uh1AZsNZjmnEiGsr4MHpNUlAi1xUrmE=
        #pub = csmoelQgK1QvyE5+XmZnXaPNt/zCgk84BG6BwfcmOFE=
  PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
  PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
  PublicKey = C6qtaptmuYQLUM5z0FXjR3ECBL85I1eYeMBlcbu5BDY=
      #priv = CD2dqWTG5PltmCZdT0KfbaJdArriOndMibTw2/CLK2w=
  AllowedIPs = 10.5.0.2/32
  Endpoint = 192.168.211.101:51820
EOF

    wg-quick up wg0
fi

# BASEDIR=/vagrant
# SYNCDIR=/vagrant/sync
# GOLANG_IMAGE=golang:1.23-bookworm
# SECONDS=0  # Reset the SECONDS variable

# usermod -a -G systemd-journal vagrant

# (cd $SYNCDIR/server_root && cp -rf --parents * /)

# set +u
# source /etc/bash.bashrc
# set -u

# export LC_ALL=en_US.UTF-8
# export LANG=en_US.UTF-8
# export DEBUG=yes
# LOGDIR="/var/log/build"


# mkdir -p "$LOGDIR"
# echo "Starting setup (out will be printed when all jobs finishes)..."

#     set -e
#     trap "echo 'build has failed!'" ERR

#     make build
#     make -C src module-debug
#     make -C src install

#     set -e
#     trap "echo 'build has failed!'" ERR


#     set -e
#     trap "echo 'build has failed!'" ERR

#     cargo install --locked --path . --root /usr --force
#     chown vagrant -R .   # Fix Rust build files ownership

#     set -e
#     trap "echo 'build has failed!'" ERR

#     sudo docker pull "$GOLANG_IMAGE"   # Add golang image to build in container
#     ci/build.sh docker

#     set -e
#     trap "echo 'build has failed!'" ERR

#     ci/build_on_docker.sh

# wait< <(jobs -p)
# echo "Waiting for build jobs to finish..."

# sleep .1
# cat ${LOGDIR}/*.log
# if grep -q ": build has failed!" ${LOGDIR}/*.log; then
#     grep -B 10 ": build has failed!" ${LOGDIR}/*.log
#     exit 1
# fi

# echo "Setting up services..."
# systemctl daemon-reload
# up fakefm.service
# up pq-upgrader

echo "GREAT SUCCESS!!! Setup took ${SECONDS}s"
