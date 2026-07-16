#!/bin/bash
set -e

sudo_exec() {
    echo 'test#123' | sudo -S "$@"
}

echo "=== 1. Deteniendo Docker y Containerd ==="
sudo_exec systemctl stop docker containerd || true

echo "=== 2. Eliminando datos fallidos en /data ==="
sudo_exec rm -rf /data/docker-data

echo "=== 3. Reestableciendo /etc/docker/daemon.json ==="
echo '{"data-root": "/docker-data"}' > /tmp/daemon.json
sudo_exec cp /tmp/daemon.json /etc/docker/daemon.json
rm -f /tmp/daemon.json

echo "=== 4. Reestableciendo /etc/containerd/config.toml ==="
cat << 'EOF' > /tmp/containerd_config.toml
disabled_plugins = ["cri"]
root = "/docker-data/containerd"
EOF
sudo_exec cp /tmp/containerd_config.toml /etc/containerd/config.toml
rm -f /tmp/containerd_config.toml

echo "=== 5. Iniciando servicios ==="
sudo_exec systemctl start containerd docker

echo "=== 6. Levantando el stack de contenedores ==="
cd /home/mquser/security-scanners
docker compose up -d
