#!/bin/bash
set -e

GITLAB_URL="http://localhost:8090"
TOKEN="glpat-MigrationToken12345"

echo "=== 1. Creando Repositorios en GitLab ==="
echo "Creando proyecto1..."
curl -s -X POST -H "PRIVATE-TOKEN: $TOKEN" -H "Content-Type: application/json" \
  "$GITLAB_URL/api/v4/projects" -d '{"name": "proyecto1", "initialize_with_readme": true, "visibility": "public"}' > /dev/null || echo "proyecto1 ya existe."

echo "Creando proyecto2..."
curl -s -X POST -H "PRIVATE-TOKEN: $TOKEN" -H "Content-Type: application/json" \
  "$GITLAB_URL/api/v4/projects" -d '{"name": "proyecto2", "initialize_with_readme": true, "visibility": "public"}' > /dev/null || echo "proyecto2 ya existe."

# Limpiar directorios locales previos
rm -rf proyecto1-local proyecto2-local

echo "=== 2. Simulación de Pushes para Proyecto 1 ==="
git clone "http://root:$TOKEN@localhost:8090/root/proyecto1.git" proyecto1-local
cd proyecto1-local

# --- Usuario 1 (proyecto1) -> Código con secreto expuesto y SQL Injection
echo "Subiendo cambios de usuario1 en proyecto1..."
git checkout -b usuario1
git config user.name "Usuario 1"
git config user.email "usuario1@example.com"
cat << 'EOF' > main.py
# Secreto expuesto
DATABASE_PASSWORD = "SuperSecretPassword123!"

# SQL injection
def get_user_data(db, search_term):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % search_term)
    return cursor.fetchall()
EOF
cp ../proyecto-test-local/.gitlab-ci.yml .
git add main.py .gitlab-ci.yml
git commit -m "Push inicial usuario1 - fallos de seguridad en codigo"
git push "http://root:$TOKEN@localhost:8090/root/proyecto1.git" usuario1 -f

# --- Usuario 2 (proyecto1) -> Dependencias vulnerables (Trivy)
echo "Subiendo cambios de usuario2 en proyecto1..."
git checkout main
git checkout -b usuario2
git config user.name "Usuario 2"
git config user.email "usuario2@example.com"
cat << 'EOF' > main.py
# Codigo limpio
print("Hello World de usuario2")
EOF
cat << 'EOF' > requirements.txt
# Vulnerabilidad antigua
django==1.11
EOF
cp ../proyecto-test-local/.gitlab-ci.yml .
git add main.py requirements.txt .gitlab-ci.yml
git commit -m "Push inicial usuario2 - dependencias obsoletas django"
git push "http://root:$TOKEN@localhost:8090/root/proyecto1.git" usuario2 -f

cd ..


echo "=== 3. Simulación de Pushes para Proyecto 2 ==="
git clone "http://root:$TOKEN@localhost:8090/root/proyecto2.git" proyecto2-local
cd proyecto2-local

# --- Usuario 3 (proyecto2) -> Código Limpio y Seguro
echo "Subiendo cambios de usuario3 en proyecto2..."
git checkout -b usuario3
git config user.name "Usuario 3"
git config user.email "usuario3@example.com"
cat << 'EOF' > main.py
# Codigo seguro
def greet_user(name):
    print(f"Hola, {name}!")

if __name__ == '__main__':
    greet_user("Usuario 3")
EOF
cp ../proyecto-test-local/.gitlab-ci.yml .
git add main.py .gitlab-ci.yml
git commit -m "Push inicial usuario3 - codigo limpio"
git push "http://root:$TOKEN@localhost:8090/root/proyecto2.git" usuario3 -f

# --- Usuario 4 (proyecto2) -> Deserialización Insegura (Semgrep)
echo "Subiendo cambios de usuario4 en proyecto2..."
git checkout main
git checkout -b usuario4
git config user.name "Usuario 4"
git config user.email "usuario4@example.com"
cat << 'EOF' > main.py
import pickle

# Deserializacion insegura con pickle
def load_session(data):
    return pickle.loads(data)
EOF
cp ../proyecto-test-local/.gitlab-ci.yml .
git add main.py .gitlab-ci.yml
git commit -m "Push inicial usuario4 - deserializacion insegura pickle"
git push "http://root:$TOKEN@localhost:8090/root/proyecto2.git" usuario4 -f

cd ..

echo "=== Simulación de Pushes en GitLab CE completada con éxito ==="
echo "Los pipelines de CI/CD se están ejecutando en segundo plano."
echo "En breve verás los reportes clasificados por proyecto y usuario en http://localhost:8081"
