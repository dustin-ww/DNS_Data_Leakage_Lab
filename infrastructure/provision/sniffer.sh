#!/bin/bash
set -e

echo "[*] Installiere Analyse-Tools: tcpdump, Zeek, tshark"

# Update & Pakete
apt-get update && apt-get install -y \
    tcpdump tshark zeek git curl vim

# Zeek-Konfiguration anpassen (optional)
mkdir -p /opt/captures

echo "[*] Sniffer bereit. Beispiel-Nutzung:"
echo "    sudo tcpdump -i eth1 -w /opt/captures/dot.pcap"
echo "    sudo zeek -r /opt/captures/dot.pcap"
