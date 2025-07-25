#!/bin/bash
# create_inventory.sh

# Generiere SSH-Konfig
vagrant ssh-config > vagrant-ssh-config

# Erstelle Inventory mit Hostnamen
cat > ./hosts_dynamic.ini << EOF
[client]
client ansible_user=vagrant ansible_python_interpreter=/usr/bin/python3

[resolver]
resolver ansible_user=vagrant ansible_python_interpreter=/usr/bin/python3

[sniffer]
sniffer ansible_user=vagrant ansible_python_interpreter=/usr/bin/python3

[all:vars]
ansible_ssh_common_args=-F vagrant-ssh-config -o StrictHostKeyChecking=no
EOF

echo "Verwende: ansible all -i hosts_dynamic.ini -m ping"