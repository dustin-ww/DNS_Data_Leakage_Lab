#!/bin/bash
set -e

echo "[*] Installiere Stubby, getdns und Tools auf Client"

# Update & Grundtools
apt-get update && apt-get install -y \
    curl gnupg2 lsb-release software-properties-common \
    build-essential pkg-config libtool libssl-dev libyaml-dev \
    libevent-dev libuv1-dev libexpat1-dev autoconf automake \
    git cmake vim net-tools dnsutils

# Stubby & getdns (manuelle Installation)
echo "[*] Baue getdns + Stubby"

cd /opt
git clone https://github.com/getdnsapi/getdns.git
cd getdns
mkdir build && cd build
cmake -DENABLE_STUBBY=ON ..
make -j$(nproc)
make install

ldconfig

# Beispielkonfiguration für Stubby
cat <<EOF > /usr/local/etc/stubby/stubby.yml
resolution_type: GETDNS_RESOLUTION_STUB
dns_transport_list:
  - GETDNS_TRANSPORT_TLS
tls_authentication: GETDNS_AUTHENTICATION_REQUIRED
round_robin_upstreams: 1
idle_timeout: 10000
listen_addresses:
  - 127.0.0.1
upstream_recursive_servers:
  - address_data: 192.168.56.11
    tls_auth_name: "resolver.local"
    tls_port: 853
EOF

echo "[*] Fertig – du kannst nun Stubby via systemd starten oder manuell."
