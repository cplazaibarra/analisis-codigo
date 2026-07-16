#!/bin/bash
set -e

sudo_exec() {
    echo 'test#123' | sudo -S "$@"
}

echo "=== 1. Creando directorio de datos en la partición raíz ==="
sudo_exec mkdir -p /docker-data

echo "=== 2. Configurando daemon.json ==="
echo '{"data-root": "/docker-data"}' > /tmp/daemon.json
sudo_exec cp /tmp/daemon.json /etc/docker/daemon.json
rm -f /tmp/daemon.json

echo "=== 3. Deteniendo Docker ==="
sudo_exec systemctl stop docker

echo "=== 4. Limpiando datos antiguos en /var ==="
sudo_exec rm -rf /var/lib/docker
sudo_exec rm -rf /var/lib/containerd

echo "=== 5. Iniciando Docker con nueva ruta ==="
sudo_exec systemctl start docker

echo "=== Almacenamiento de Docker reconfigurado con éxito ==="
