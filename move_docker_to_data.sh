#!/bin/bash
set -e

sudo_exec() {
    echo 'test#123' | sudo -S "$@"
}

echo "=== 1. Deteniendo Docker y Containerd ==="
sudo_exec systemctl stop docker containerd

echo "=== 2. Moviendo datos a la partición /data ==="
if [ -d /docker-data ] && [ ! -d /data/docker-data ]; then
    sudo_exec mv /docker-data /data/docker-data
    echo "Datos movidos correctamente a /data/docker-data"
else
    sudo_exec mkdir -p /data/docker-data
fi

echo "=== 3. Actualizando /etc/docker/daemon.json ==="
echo '{"data-root": "/data/docker-data"}' > /tmp/daemon.json
sudo_exec cp /tmp/daemon.json /etc/docker/daemon.json
rm -f /tmp/daemon.json

echo "=== 4. Actualizando /etc/containerd/config.toml ==="
cat << 'EOF' > /tmp/containerd_config.toml
disabled_plugins = ["cri"]
root = "/data/docker-data/containerd"
EOF
sudo_exec cp /tmp/containerd_config.toml /etc/containerd/config.toml
rm -f /tmp/containerd_config.toml

echo "=== 5. Iniciando servicios ==="
sudo_exec systemctl start containerd docker

echo "=== Almacenamiento migrado a /data con éxito ==="
