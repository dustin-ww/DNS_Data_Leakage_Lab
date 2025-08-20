#!/bin/bash
# create_inventory.sh

# Generiere SSH-Konfig
vagrant ssh-config > vagrant-ssh-config

# Erstelle Inventory mit Hostnamen
cat > ./hosts_dynamic.ini << EOF
[client]
client ansible_user=vagrant ansible_python_interpreter=/usr/bin/python3 data_source_dir=/home/dustin/Dev/DNS_Data_Leakage_Lab/data python_source_dir=/home/dustin/Dev/DNS_Data_Leakage_Lab


[all:vars]
ansible_ssh_common_args=-F ./vagrant/vagrant-ssh-config -o StrictHostKeyChecking=no
EOF

echo "Verwende: ansible all -i hosts_dynamic.ini -m ping"