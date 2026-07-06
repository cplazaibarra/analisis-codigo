#!/bin/bash
set -e

# Configuración básica
GITEA_URL="http://localhost:3000"
RECEIVER_URL="http://webhook-receiver:5000/webhook"
PASSWORD="PasswordUsuario123"

echo "=== 1. Creando Usuarios en Gitea ==="
for i in {1..3}; do
  username="usuario$i"
  email="usuario$i@example.com"
  echo "Creando usuario: $username..."
  # Si ya existe, el comando fallará pero continuaremos
  docker exec -u git gitea-server gitea admin user create --username "$username" --password "$PASSWORD" --email "$email" --must-change-password=false || echo "Usuario $username ya existe."
done

echo "=== 2. Creando Repositorios y Webhooks ==="
for i in {1..3}; do
  username="usuario$i"
  repo="proyecto$i"
  
  echo "Creando repositorio $username/$repo..."
  curl -s -X POST -H "Content-Type: application/json" -u "$username:$PASSWORD" \
    "$GITEA_URL/api/v1/user/repos" -d "{\"name\":\"$repo\", \"private\":false, \"auto_init\":true}" > /dev/null

  echo "Configurando Webhook para $username/$repo..."
  curl -s -X POST -H "Content-Type: application/json" -u "$username:$PASSWORD" \
    "$GITEA_URL/api/v1/repos/$username/$repo/hooks" \
    -d "{\"type\":\"gitea\", \"config\":{\"url\":\"$RECEIVER_URL\", \"content_type\":\"json\"}, \"events\":[\"push\"], \"active\":true}" > /dev/null
done

echo "=== 3. Clonando Repositorios y Preparando Código ==="
# Limpiar directorios de simulación previos
rm -rf proyecto1-local proyecto2-local proyecto3-local

# --- PROYECTO 1 (usuario1) -> Vulnerabilidades en código (Semgrep)
echo "Configurando proyecto1-local para usuario1..."
git clone "$GITEA_URL/usuario1/proyecto1.git" proyecto1-local
cd proyecto1-local
git config user.name "usuario1"
git config user.email "usuario1@example.com"
cat << 'EOF' > main.py
# Vulnerabilidad 1: Secreto expuesto
AWS_KEY = "AKIAIMNOJVQIHX7234SA"

# Vulnerabilidad 2: SQL Injection
def search_user(db, search):
    cursor = db.cursor()
    query = f"SELECT * FROM accounts WHERE name = '{search}'"
    cursor.execute(query)
    return cursor.fetchall()
EOF
git add main.py
git commit -m "Push inicial usuario1 - con fallos de Semgrep"
git push http://usuario1:$PASSWORD@localhost:3000/usuario1/proyecto1.git main
cd ..

# --- PROYECTO 2 (usuario2) -> Vulnerabilidades en dependencias (Trivy)
echo "Configurando proyecto2-local para usuario2..."
git clone "$GITEA_URL/usuario2/proyecto2.git" proyecto2-local
cd proyecto2-local
git config user.name "usuario2"
git config user.email "usuario2@example.com"
cat << 'EOF' > main.py
# Código seguro
print("Hello World de usuario2")
EOF
cat << 'EOF' > requirements.txt
# Vulnerabilidad: versión antigua de Flask
flask==0.12
EOF
git add main.py requirements.txt
git commit -m "Push inicial usuario2 - con dependencias obsoletas"
git push http://usuario2:$PASSWORD@localhost:3000/usuario2/proyecto2.git main
cd ..

# --- PROYECTO 3 (usuario3) -> Código Seguro
echo "Configurando proyecto3-local para usuario3..."
git clone "$GITEA_URL/usuario3/proyecto3.git" proyecto3-local
cd proyecto3-local
git config user.name "usuario3"
git config user.email "usuario3@example.com"
cat << 'EOF' > main.py
# Código seguro, sin eval ni SQL inyección, y parametrizado
def get_message():
    return "Proyecto seguro y limpio de usuario3"

if __name__ == "__main__":
    print(get_message())
EOF
git add main.py
git commit -m "Push inicial usuario3 - código limpio"
git push http://usuario3:$PASSWORD@localhost:3000/usuario3/proyecto3.git main
cd ..

echo "=== Simulación de Pushes completada ==="
echo "Los análisis asíncronos se están ejecutando en segundo plano."
