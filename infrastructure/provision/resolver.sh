#!/bin/bash
set -e

echo "[*] Installiere Unbound mit TLS-Unterstützung auf Resolver"

# Update & Tools
apt-get update && apt-get install -y unbound openssl dnsutils

# TLS-Zertifikate generieren (self-signed)
echo "[*] Erzeuge self-signed TLS-Zertifikat für Unbound"

mkdir -p /etc/unbound/tls

openssl req -x509 -newkey rsa:2048 -nodes -keyout /etc/unbound/tls/unbound.key \
    -out /etc/unbound/tls/unbound.crt -days 365 \
    -subj "/CN=resolver.local"

# Beispielkonfiguration
cat <<EOF > /etc/unbound/unbound.conf
server:
    verbosity: 1
    interface: 0.0.0.0
    port: 53
    do-tcp: yes
    do-udp: yes
    do-tls: yes
    tls-port: 853
    tls-service-key: "/etc/unbound/tls/unbound.key"
    tls-service-pem: "/etc/unbound/tls/unbound.crt"
    access-control: 0.0.0.0/0 allow
    hide-identity: yes
    hide-version: yes

forward-zone:
    name: "."
    forward-addr: 1.1.1.1@853
    forward-ssl-upstream: yes
EOF

systemctl restart unbound

echo "[*] Unbound mit DoT läuft auf Port 853"
