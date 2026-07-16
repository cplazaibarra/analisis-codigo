#!/bin/bash
set -e

sudo_exec() {
    echo 'test#123' | sudo -S "$@"
}

echo "=== 1. Creando directorio de containerd en la partición raíz ==="
sudo_exec mkdir -p /docker-data/containerd

echo "=== 2. Configurando /etc/containerd/config.toml ==="
cat << 'EOF' > /tmp/containerd_config.toml
disabled_plugins = ["cri"]
root = "/docker-data/containerd"
EOF
sudo_exec cp /tmp/containerd_config.toml /etc/containerd/config.toml
rm -f /tmp/containerd_config.toml

echo "=== 3. Deteniendo servicios ==="
sudo_exec systemctl stop docker containerd

echo "=== 4. Limpiando datos antiguos de /var ==="
sudo_exec rm -rf /var/lib/containerd

echo "=== 5. Reiniciando servicios ==="
sudo_exec systemctl start containerd docker

echo "=== containerd reconfigurado con éxito ==="
