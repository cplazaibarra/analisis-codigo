#!/bin/bash
# Script to automate the creation of the "SCAN-CODE" VM on KVM rootlessly
set -e

VM_NAME="SCAN-CODE"
CLOUD_IMAGE_URL="https://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-amd64.img"
TMP_DIR="/tmp/scan-code-vm-setup"

echo "=== 1. Preparando directorios ==="
mkdir -p "$TMP_DIR"
cd "$TMP_DIR"

echo "=== 2. Descargando imagen oficial de Ubuntu 22.04 LTS (Cloud Image) ==="
if [ ! -f "ubuntu-22.04-server-cloudimg-amd64.img" ]; then
    wget -q --show-progress "$CLOUD_IMAGE_URL" -O ubuntu-22.04-server-cloudimg-amd64.img
fi

echo "=== 3. Creando archivos de configuración Cloud-Init ==="
# Generando el archivo de inicialización del sistema y preinstalación de paquetes
cat << 'EOF' > user-data
#cloud-config
hostname: SCAN-CODE
timezone: America/Santiago
ssh_pwauth: true

users:
  - name: mquser
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    passwd: "$6$rounds=4096$saltString$N1pZ7N6JmFz9V9L6K6.ZlUfJkK2qT3y1pP/Gz1z0q0o4d3v1.t.y9y8y7y6y5y4y3y2y1y0y/Z0z1" # test#123
    ssh_authorized_keys:
      - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB4CtnAWudIm8e2yYSqm9fkuzJbN8Cy46bD1BkoUNp9u christian.plaza.ibarra@gmail.com

apt:
  sources:
    trivy.list:
      source: "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main"
      keyid: 17A42A5C9738A0F2 # Add GPG Key

package_update: true
package_upgrade: true

packages:
  - git
  - python3-pip
  - python3-venv
  - curl
  - wget
  - sqlite3
  - apt-transport-https
  - gnupg

runcmd:
  # 1. Instalar llave GPG de Trivy e instalar el paquete
  - wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg
  - apt-get update
  - apt-get install -y trivy
  
  # 2. Instalar Semgrep globalmente via pip
  - pip3 install semgrep
  
  # 3. Preparar el directorio de la aplicación de reportes
  - mkdir -p /home/mquser/central-scanner
  - chown -R mquser:mquser /home/mquser/central-scanner
  - runas -u mquser -- python3 -m venv /home/mquser/central-scanner/venv
  - runas -u mquser -- /home/mquser/central-scanner/venv/bin/pip install flask flask-sqlalchemy requests pyyaml

final_message: "La maquina virtual SCAN-CODE se ha inicializado correctamente."
EOF

cat << 'EOF' > meta-data
local-hostname: SCAN-CODE
instance-id: scan-code-02
EOF

echo "=== 4. Generando imagen de semilla (seed.iso) ==="
cloud-localds seed.iso user-data meta-data
# Asegurar permisos de lectura para el demonio qemu
chmod 644 seed.iso

echo "=== 5. Gestionando almacenamiento en pool default ==="
# Remover la VM si ya existía para evitar conflictos
if virsh dominfo "$VM_NAME" &>/dev/null; then
    echo "Deteniendo y removiendo VM existente..."
    virsh destroy "$VM_NAME" || true
    virsh undefine "$VM_NAME" || true
fi

# Eliminar volumen viejo si existía
virsh vol-delete --pool default "${VM_NAME}.qcow2" || true

# Crear volumen en pool default con el tamaño exacto de la imagen descargada
IMAGE_SIZE=$(stat -c%s ubuntu-22.04-server-cloudimg-amd64.img)
virsh vol-create-as default "${VM_NAME}.qcow2" "$IMAGE_SIZE" --format qcow2

# Subir la imagen de Ubuntu al volumen creado
echo "Subiendo imagen al volumen de almacenamiento..."
virsh vol-upload --pool default "${VM_NAME}.qcow2" ubuntu-22.04-server-cloudimg-amd64.img

# Expandir el volumen a 20GB
echo "Redimensionando el disco de la VM a 20GB..."
virsh vol-resize --pool default "${VM_NAME}.qcow2" 20G

echo "=== 6. Levantando la VM en KVM ==="
virt-install \
  --name "$VM_NAME" \
  --memory 2048 \
  --vcpus 2 \
  --disk "vol=default/${VM_NAME}.qcow2,device=disk,bus=virtio" \
  --disk "$TMP_DIR/seed.iso,device=cdrom" \
  --network network=default \
  --os-variant ubuntu22.04 \
  --graphics none \
  --import \
  --noautoconsole

echo "=== 7. Máquina virtual creada y arrancando ==="
echo "Puedes comprobar el estado de la VM ejecutando:"
echo "  virsh list --all"
echo ""
echo "Para averiguar la dirección IP asignada a la VM una vez inicie (puede tardar 1-2 minutos):"
echo "  virsh domifaddr $VM_NAME"
echo ""
echo "Para conectar por SSH:"
echo "  ssh mquser@<IP_ASIGNADA> (Password: test#123 o via SSH Key)"
echo ""

# Limpieza básica de la semilla local en /tmp
rm -f user-data meta-data
