#!/bin/bash
set -e

# Autenticar sudo pasando la contraseña
sudo_exec() {
    echo 'test#123' | sudo -S "$@"
}

echo "=== 1. Actualizando paquetes e instalando dependencias ==="
sudo_exec apt-get update
sudo_exec apt-get install -y ca-certificates curl gnupg

echo "=== 2. Configurando GPG Key de Docker ==="
sudo_exec install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /tmp/docker.gpg
sudo_exec gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg /tmp/docker.gpg
rm -f /tmp/docker.gpg
sudo_exec chmod a+r /etc/apt/keyrings/docker.gpg

echo "=== 3. Configurando repositorio de Docker ==="
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /tmp/docker.list
sudo_exec cp /tmp/docker.list /etc/apt/sources.list.d/docker.list
rm -f /tmp/docker.list

echo "=== 4. Instalando Docker Engine y Docker Compose ==="
sudo_exec apt-get update
sudo_exec apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

echo "=== 5. Habilitando servicio Docker ==="
sudo_exec systemctl enable docker
sudo_exec systemctl start docker

echo "=== 6. Agregando usuario mquser al grupo docker ==="
sudo_exec usermod -aG docker mquser

echo "=== Docker instalado y configurado correctamente ==="
