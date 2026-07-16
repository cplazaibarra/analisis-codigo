#!/bin/bash
set -e

GITLAB_URL="http://172.27.103.42:8090"
TOKEN="glpat-MigrationToken12345"

echo "=== 1. Limpieza de directorios locales ==="
rm -rf proyecto1-remote-local proyecto2-remote-local

# Vulnerable requirements.txt para Trivy y dependencias del código vulnerable
cat << 'EOF' > requirements.txt
jinja2==2.10.1
Django==1.11.29
urllib3==1.25.7
requests==2.20.0
cryptography==2.8
pyyaml==5.3
EOF

echo "=== 2. Simulación de Pushes para Proyecto 1 ==="
git clone "http://root:$TOKEN@172.27.103.42:8090/root/proyecto1.git" proyecto1-remote-local
cd proyecto1-remote-local

# --- Usuario 1 (proyecto1) -> SQLi, Command Injection, YAML inseguro y TempFiles
echo "Subiendo cambios de usuario1 en proyecto1..."
git checkout -b usuario1 || git checkout usuario1
git config user.name "Usuario 1"
git config user.email "usuario1@example.com"
cat << 'EOF' > main.py
import sqlite3
import os
import subprocess
import tempfile
import yaml

def find_user(username):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    # 1. SQL injection
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
    return cursor.fetchall()

def ping_server(ip_address):
    # 2. Command injection via os.system
    os.system("ping -c 1 " + ip_address)

def execute_user_script(script_path):
    # 3. Command injection via subprocess.Popen with shell=True
    subprocess.Popen(script_path, shell=True, stdout=subprocess.PIPE)

def create_temp_report():
    # 4. Insecure temporary file creation (mktemp)
    temp_file = tempfile.mktemp()
    with open(temp_file, "w") as f:
        f.write("Report Data")
    return temp_file

def load_user_config(config_data):
    # 5. Unsafe YAML loading (Deserialization vulnerability)
    return yaml.load(config_data, Loader=yaml.Loader)
EOF
cp ../requirements.txt .
cp ../proyecto-test-local/.gitlab-ci.yml .
git add main.py requirements.txt .gitlab-ci.yml
git commit -m "Push de usuario1 - Multiples vulnerabilidades OWASP (SQLi, Command Injection, mktemp, YAML)"
git commit --allow-empty -m "Re-trigger pipeline to test expanded Semgrep rules"
git push "http://root:$TOKEN@172.27.103.42:8090/root/proyecto1.git" usuario1 -f

# --- Usuario 2 (proyecto1) -> Secrets, Insecure Hash, SSLv3, Weak Cookies
echo "Subiendo cambios de usuario2 en proyecto1..."
git checkout main
git checkout -b usuario2 || git checkout usuario2
git config user.name "Usuario 2"
git config user.email "usuario2@example.com"
cat << 'EOF' > main.py
import hashlib
import ssl
from flask import Flask, make_response

app = Flask(__name__)

# 1. Hardcoded Secrets
SLACK_TOKEN = "slack_token_xoxb_dummy"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
ADMIN_PASSWORD = "super_secret_hardcoded_pass_123"

def hash_user_password(password):
    # 2. Weak hashing algorithm (MD5)
    return hashlib.md5(password.encode()).hexdigest()

def verify_old_hash(password):
    # 3. Weak hashing algorithm (SHA1)
    return hashlib.sha1(password.encode()).hexdigest()

def connect_to_legacy_server():
    # 4. Insecure SSLv3 protocol usage
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
    # 5. Disable certificate verification
    context.verify_mode = ssl.CERT_NONE
    return context

@app.route('/login')
def login():
    resp = make_response("LoggedIn")
    # 6. Insecure Cookie settings (missing HttpOnly and Secure flags)
    resp.set_cookie('auth_session', 'session-value', secure=False, httponly=False)
    return resp
EOF
cp ../requirements.txt .
cp ../proyecto-test-local/.gitlab-ci.yml .
git add main.py requirements.txt .gitlab-ci.yml
git commit -m "Push de usuario2 - Secrets, MD5, SHA1, SSLv3 y Cookies inseguras"
git commit --allow-empty -m "Re-trigger pipeline to test expanded Semgrep rules"
git push "http://root:$TOKEN@172.27.103.42:8090/root/proyecto1.git" usuario2 -f

cd ..


echo "=== 3. Simulación de Pushes para Proyecto 2 ==="
git clone "http://root:$TOKEN@172.27.103.42:8090/root/proyecto2.git" proyecto2-remote-local
cd proyecto2-remote-local

# --- Usuario 2 (proyecto2) -> Pickle, Weak PRNG, Weak Ciphers, XXE
echo "Subiendo cambios de usuario2 en proyecto2..."
git checkout -b usuario2 || git checkout usuario2
git config user.name "Usuario 2"
git config user.email "usuario2@example.com"
cat << 'EOF' > main.py
import pickle
import random
import xml.etree.ElementTree as ET
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def load_data(raw_data):
    # 1. Unsafe deserialization via pickle
    return pickle.loads(raw_data)

def generate_session_token():
    # 2. Insecure Random Number Generation for tokens
    token = ""
    for _ in range(16):
        token += chr(random.randint(97, 122))
    return token

def encrypt_legacy_data(key, data):
    # 3. Weak cipher algorithm (RC4) and insecure ECB mode
    cipher = Cipher(algorithms.ARC4(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(data)

def parse_user_xml(xml_string):
    # 4. XML External Entity (XXE) vulnerability
    parser = ET.XMLParser()
    return ET.fromstring(xml_string, parser=parser)
EOF
cp ../requirements.txt .
cp ../proyecto-test-local/.gitlab-ci.yml .
git add main.py requirements.txt .gitlab-ci.yml
git commit -m "Push de usuario2 en proyecto2 - Pickle, Weak PRNG, RC4, ECB y XXE"
git commit --allow-empty -m "Re-trigger pipeline to test expanded Semgrep rules"
git push "http://root:$TOKEN@172.27.103.42:8090/root/proyecto2.git" usuario2 -f

# --- Usuario 3 (proyecto2) -> Raw SQL Format, Weak Assert, SSTI, FTP
echo "Subiendo cambios de usuario3 en proyecto2..."
git checkout main
git checkout -b usuario3 || git checkout usuario3
git config user.name "Usuario 3"
git config user.email "usuario3@example.com"
cat << 'EOF' > main.py
import sqlite3
import ftplib
from flask import Flask, render_template_string, request

app = Flask(__name__)

def get_orders(user_id):
    conn = sqlite3.connect('orders.db')
    cursor = conn.cursor()
    # 1. SQL Injection via raw string formatting
    query = "SELECT * FROM orders WHERE user_id = %s" % user_id
    cursor.execute(query)
    return cursor.fetchall()

def verify_token(token):
    # 2. Weak use of assert statement for security verification
    assert token is not None, "Token cannot be null"
    return True

@app.route('/greet')
def greet():
    user_input = request.args.get('name', 'Guest')
    # 3. Server-Side Template Injection (SSTI) / XSS
    return render_template_string("Hello " + user_input)

def backup_reports():
    # 4. Insecure FTP connection (cleartext communication)
    ftp = ftplib.FTP('ftp.legacy-system.com')
    ftp.login('anonymous', '')
    ftp.quit()
EOF
cp ../requirements.txt .
cp ../proyecto-test-local/.gitlab-ci.yml .
git add main.py requirements.txt .gitlab-ci.yml
git commit -m "Push de usuario3 en proyecto2 - SQL Injection, weak assert, SSTI, FTP"
git commit --allow-empty -m "Re-trigger pipeline to test expanded Semgrep rules"
git push "http://root:$TOKEN@172.27.103.42:8090/root/proyecto2.git" usuario3 -f

cd ..

rm -f requirements.txt
echo "=== Simulación completada con éxito ==="
