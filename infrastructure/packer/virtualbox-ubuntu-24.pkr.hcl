packer {
  required_plugins {
    virtualbox = {
      version = ">= 1.1.2"
      source  = "github.com/hashicorp/virtualbox"
    }
    vagrant = {
      version = "~> 1"
      source = "github.com/hashicorp/vagrant"
    }
  }
}

source "virtualbox-iso" "basic-lab-ubuntu" {
  guest_os_type = "Ubuntu_64"
  iso_url       = "https://releases.ubuntu.com/24.04.2/ubuntu-24.04.2-live-server-amd64.iso"
  iso_checksum  = "sha256:d6dab0c3a657988501b4bd76f1297c053df710e06e0c3aece60dead24f270b4d"
  
  # VM-Einstellungen
  memory    = 4096
  cpus      = 4
  disk_size = 20480
  
  # SSH-Konfiguration
  ssh_username = "admin"
  ssh_password = "packerubuntu"
  ssh_timeout = "2h"  # Timeout erhöht
  ssh_port = "22"
  
  # Autoinstall-Konfiguration
  http_directory   = "autoinstall"
  output_directory = "output/ubuntu-jammy-autoinstall"
  shutdown_command = "sudo -S shutdown -P now"
  
  # Hardware-Konfiguration
  hard_drive_interface   = "sata"
  
  # Korrigierte Boot-Kommandos für Ubuntu 24.04
  boot_command            = ["<wait5><wait5>yes<enter><wait>"]
  boot_wait               = "2m30s"
  cd_files                = ["./autoinstall/user-data", "./autoinstall/meta-data"]
  cd_label                = "cidata"

  guest_additions_mode   = "attach"
}

build {
  sources = ["source.virtualbox-iso.basic-lab-ubuntu"]

  provisioner "shell" {
    inline            = ["uptime"]
    pause_before      = "1m"
    timeout           = "15m0s"
  }

  provisioner "shell" {
    inline            = ["sudo -S cloud-init status --wait"]
    timeout           = "15m0s"
  }

    provisioner "shell" {
    pause_before = "30s"
    timeout      = "15m0s"
    environment_vars = [
      "DEBIAN_FRONTEND=noninteractive"
    ]
    inline = [
      # System aktualisieren und Guest Additions aus den Ubuntu-Repositories installieren
      "sudo apt-get update",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y virtualbox-guest-utils virtualbox-guest-additions-iso",
      
      # Optional: Kernel-Headers falls noch nicht installiert (für DKMS-Module)
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y linux-headers-$(uname -r)",
      
      # Prüfen ob Guest Additions erfolgreich installiert wurden
      "if command -v VBoxControl >/dev/null 2>&1; then",
      "  echo 'VirtualBox Guest Additions successfully installed'",
      "  VBoxControl --version",
      "else",
      "  echo 'Warning: VBoxControl not found after installation'",
      "fi",
      
      # VirtualBox Guest Services aktivieren (falls nicht automatisch gestartet)
      "sudo systemctl enable vboxadd || echo 'vboxadd service not available'",
      "sudo systemctl enable vboxadd-service || echo 'vboxadd-service not available'"
    ]
  }


  post-processor "vagrant" {
    keep_input_artifact  = false
    compression_level    = 0
    output               = "./vagrant_output/basic-ubuntu24.box"
  }

}