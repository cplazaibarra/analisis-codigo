import os
import subprocess
import shutil
import json
import threading
import requests
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from flask import Flask, request, jsonify

app = Flask(__name__)
HTML_DIR = "/app/html"
SCANS_DIR = "/app/scans"
HOST_SCANS_DIR = os.environ.get("HOST_SCANS_DIR", "/home/cplaza/.gemini/antigravity/scratch/security-scanners/scans")
EXTERNAL_REPORTS_URL = os.environ.get("EXTERNAL_REPORTS_URL", "http://localhost:8081")

GITEA_ADMIN_USER = os.environ.get("GITEA_ADMIN_USER")
GITEA_ADMIN_PASS = os.environ.get("GITEA_ADMIN_PASS")
GITEA_URL = os.environ.get("GITEA_URL", "http://gitea-server:3000")

def post_gitea_status(owner, repo, sha, context, state, description, target_url=None):
    """
    Envía una actualización del estado de commit (checks verde/rojo) a la API de Gitea.
    """
    if not sha or sha == "0000000000000000000000000000000000000000":
        print(f"Saltando envío de estado de commit (SHA de commit inválido o de prueba: {sha})")
        return
        
    url = f"{GITEA_URL}/api/v1/repos/{owner}/{repo}/statuses/{sha}"
    payload = {
        "state": state,          # "pending", "success", "warning", "error", "failure"
        "context": context,      # Identificador único (ej: "security/semgrep")
        "description": description
    }
    if target_url:
        payload["target_url"] = target_url
        
    try:
        r = requests.post(
            url, 
            json=payload, 
            auth=(GITEA_ADMIN_USER, GITEA_ADMIN_PASS),
            headers={"Content-Type": "application/json"}
        )
        if r.status_code != 201:
            print(f"Error al enviar estado a Gitea ({r.status_code}): {r.text}")
        else:
            print(f"Estado '{state}' enviado correctamente a Gitea para '{context}'")
    except Exception as e:
        print(f"Error de red al actualizar estado en Gitea: {e}")

def send_email_report(to_email, repo_name, branch, semgrep_count, trivy_count, semgrep_path, trivy_path):
    """
    Envía un correo con el resumen del push y adjunta los reportes HTML de Semgrep y Trivy.
    """
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port_str = os.environ.get("SMTP_PORT", "587")
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")
    smtp_from = os.environ.get("SMTP_FROM", smtp_user)

    if not smtp_host or not smtp_user or not smtp_pass or smtp_host == "smtp.example.com":
        print("Configuración SMTP por defecto o incompleta. Saltando envío de correo.")
        return

    try:
        smtp_port = int(smtp_port_str)
    except ValueError:
        smtp_port = 587

    print(f"Preparando envío de correo de reporte de seguridad a {to_email}...")

    # Crear mensaje multipart
    msg = MIMEMultipart()
    msg['From'] = smtp_from
    msg['To'] = to_email
    msg['Subject'] = f"🛡️ Reporte de Seguridad: {repo_name} (rama: {branch})"

    # Definir etiquetas de color según resultados
    semgrep_color = "#ef4444" if semgrep_count > 0 else "#10b981"
    trivy_color = "#ef4444" if trivy_count > 0 else "#10b981"

    # Cuerpo del correo en HTML
    html_body = f"""
    <html>
    <body style="font-family: 'Segoe UI', Arial, sans-serif; background-color: #f4f4f5; padding: 20px; color: #1f2937;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 30px; border-radius: 12px; border: 1px solid #e5e7eb; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
            <h2 style="color: #0f172a; margin-top: 0; font-size: 24px; border-bottom: 2px solid #f3f4f6; padding-bottom: 15px;">🛡️ Security Scan Report</h2>
            <p style="font-size: 16px; line-height: 1.5;">Se ha completado el análisis de seguridad automático tras tu último <strong>git push</strong>.</p>
            
            <div style="background-color: #f9fafb; border-radius: 8px; padding: 20px; margin: 20px 0; border: 1px solid #f3f4f6;">
                <table style="width: 100%; border-collapse: collapse; font-size: 15px;">
                    <tr>
                        <td style="padding: 6px 0; color: #6b7280; width: 40%;"><strong>Repositorio:</strong></td>
                        <td style="padding: 6px 0; color: #111827;"><strong>{repo_name}</strong></td>
                    </tr>
                    <tr>
                        <td style="padding: 6px 0; color: #6b7280;"><strong>Rama:</strong></td>
                        <td style="padding: 6px 0;"><span style="background-color: #e2e8f0; color: #334155; padding: 2px 8px; border-radius: 4px; font-family: monospace; font-size: 14px;">{branch}</span></td>
                    </tr>
                    <tr style="border-top: 1px solid #e5e7eb;">
                        <td style="padding: 12px 0 6px 0; color: #6b7280;"><strong>Fallas Semgrep (SAST):</strong></td>
                        <td style="padding: 12px 0 6px 0; font-weight: bold; color: {semgrep_color}; font-size: 16px;">{semgrep_count}</td>
                    </tr>
                    <tr>
                        <td style="padding: 6px 0; color: #6b7280;"><strong>Vulnerabilidades Trivy:</strong></td>
                        <td style="padding: 6px 0; font-weight: bold; color: {trivy_color}; font-size: 16px;">{trivy_count}</td>
                    </tr>
                </table>
            </div>

            <p style="font-size: 14px; color: #4b5563;">Puedes revisar los reportes web interactivos haciendo clic en los botones de abajo o abrir los archivos HTML adjuntos a este correo:</p>
            
            <div style="text-align: center; margin: 30px 0 10px 0;">
                <a href="{EXTERNAL_REPORTS_URL}/{repo_name}-{branch}-semgrep.html" style="background-color: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; margin-right: 10px; display: inline-block; font-size: 14px;">🔍 Reporte Semgrep</a>
                <a href="{EXTERNAL_REPORTS_URL}/{repo_name}-{branch}-trivy.html" style="background-color: #d97706; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block; font-size: 14px;">🛡️ Reporte Trivy</a>
            </div>
            
            <hr style="border: 0; border-top: 1px solid #e5e7eb; margin: 30px 0 15px 0;">
            <p style="font-size: 12px; color: #9ca3af; text-align: center;">Este es un mensaje generado automáticamente por el sistema de auditoría centralizado.</p>
        </div>
    </body>
    </html>
    """
    msg.attach(MIMEText(html_body, 'html'))

    # Adjuntar reportes como archivos HTML
    for path, filename in [(semgrep_path, f"{repo_name}-{branch}-semgrep.html"), 
                           (trivy_path, f"{repo_name}-{branch}-trivy.html")]:
        if path and os.path.exists(path):
            try:
                with open(path, "rb") as attachment:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(attachment.read())
                    encoders.encode_base64(part)
                    part.add_header("Content-Disposition", f"attachment; filename= {filename}")
                    msg.attach(part)
            except Exception as ex_attach:
                print(f"Error al adjuntar archivo {filename}: {ex_attach}")

    # Conectar a SMTP y enviar
    try:
        server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(smtp_from, to_email, msg.as_string())
        server.quit()
        print(f"Correo de reporte enviado correctamente a {to_email}")
    except Exception as e:
        print(f"Error al enviar correo SMTP a {to_email}: {e}")

def generate_semgrep_html(json_data, html_path, repo_name, branch):
    """
    Convierte el resultado JSON de Semgrep en una página HTML interactiva y premium.
    """
    results = json_data.get("results", [])
    errors = json_data.get("errors", [])
    
    # Calcular estadísticas
    total_findings = len(results)
    severity_counts = {"ERROR": 0, "WARNING": 0, "INFO": 0}
    for r in results:
        sev = r.get("extra", {}).get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Construir filas de la tabla
    rows_html = ""
    for idx, r in enumerate(results):
        path = r.get("path")
        line = r.get("start", {}).get("line")
        col = r.get("start", {}).get("col")
        extra = r.get("extra", {})
        message = extra.get("message", "")
        severity = extra.get("severity", "INFO")
        code_lines = extra.get("lines", "").replace("<", "&lt;").replace(">", "&gt;")
        
        metadata = extra.get("metadata", {})
        cwe_list = metadata.get("cwe", [])
        cwe_str = ", ".join(cwe_list) if isinstance(cwe_list, list) else str(cwe_list)
        
        badge_class = "bg-danger text-white" if severity == "ERROR" else ("bg-warning text-dark" if severity == "WARNING" else "bg-info text-dark")

        rows_html += f"""
        <tr class="issue-row" data-severity="{severity}">
            <td><span class="badge {badge_class}">{severity}</span></td>
            <td><strong>{path}</strong>:L{line}:{col}</td>
            <td>
                <div>{message}</div>
                {f'<div class="text-muted small mt-1"><strong>CWE:</strong> {cwe_str}</div>' if cwe_str else ''}
                <div class="mt-2">
                    <button class="btn btn-sm btn-outline-secondary btn-code" onclick="toggleCode({idx})">Mostrar Código</button>
                    <pre id="code-{idx}" class="code-block mt-2" style="display:none;"><code>{code_lines}</code></pre>
                </div>
            </td>
        </tr>
        """

    if not results:
        rows_html = """
        <tr>
            <td colspan="3" class="text-center text-success py-5">
                <h4>🎉 ¡Felicidades! No se encontraron vulnerabilidades ni errores de código.</h4>
            </td>
        </tr>
        """

    html_content = f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Reporte Semgrep (SAST) - {repo_name} ({branch})</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {{
                background-color: #0f172a;
                color: #e2e8f0;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }}
            .card-stat {{
                border: none;
                border-radius: 12px;
                padding: 20px;
                transition: transform 0.2s;
            }}
            .card-stat:hover {{
                transform: translateY(-5px);
            }}
            .card-total {{ background: linear-gradient(135deg, #3b82f6, #1d4ed8); color: white; }}
            .card-error {{ background: linear-gradient(135deg, #ef4444, #b91c1c); color: white; }}
            .card-warning {{ background: linear-gradient(135deg, #f59e0b, #d97706); color: white; }}
            .card-info {{ background: linear-gradient(135deg, #10b981, #047857); color: white; }}
            .table-container {{
                background-color: #1e293b;
                border-radius: 12px;
                padding: 20px;
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            }}
            .table {{
                color: #e2e8f0;
            }}
            .table th {{
                border-bottom: 2px solid #334155;
                color: #94a3b8;
            }}
            .table td {{
                border-bottom: 1px solid #334155;
                vertical-align: middle;
            }}
            .code-block {{
                background-color: #0f172a;
                color: #38bdf8;
                padding: 12px;
                border-radius: 6px;
                border: 1px solid #334155;
                font-family: 'Courier New', Courier, monospace;
                overflow-x: auto;
            }}
            .btn-code {{
                font-size: 0.8rem;
            }}
        </style>
    </head>
    <body>
        <div class="container py-5">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <div>
                    <h1 class="fw-bold">Reporte Semgrep (SAST)</h1>
                    <p class="text-muted">Proyecto: <strong>{repo_name}</strong> | Rama: <strong>{branch}</strong></p>
                </div>
                <div class="text-end">
                    <span class="badge bg-secondary p-2">Generado: {timestamp}</span>
                </div>
            </div>

            <!-- Estadísticas -->
            <div class="row g-4 mb-5">
                <div class="col-md-3">
                    <div class="card-stat card-total">
                        <h5>Total de Hallazgos</h5>
                        <h2 class="fw-bold">{total_findings}</h2>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card-stat card-error">
                        <h5>Errores (Altos)</h5>
                        <h2 class="fw-bold">{severity_counts['ERROR']}</h2>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card-stat card-warning">
                        <h5>Advertencias (Medios)</h5>
                        <h2 class="fw-bold">{severity_counts['WARNING']}</h2>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card-stat card-info">
                        <h5>Info (Bajos)</h5>
                        <h2 class="fw-bold">{severity_counts['INFO']}</h2>
                    </div>
                </div>
            </div>

            <!-- Tabla de Hallazgos -->
            <div class="table-container">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h4 class="m-0 fw-bold">Listado de Hallazgos</h4>
                    <div>
                        <select id="severity-filter" class="form-select bg-dark text-white border-secondary btn-sm" onchange="filterSeverity()">
                            <option value="ALL">Mostrar Todos</option>
                            <option value="ERROR">Errores (Altos)</option>
                            <option value="WARNING">Advertencias (Medios)</option>
                            <option value="INFO">Info (Bajos)</option>
                        </select>
                    </div>
                </div>
                
                <div class="table-responsive">
                    <table class="table">
                        <thead>
                            <tr>
                                <th style="width: 15%">Severidad</th>
                                <th style="width: 25%">Archivo y Línea</th>
                                <th style="width: 60%">Descripción y Código</th>
                            </tr>
                        </thead>
                        <tbody>
                            {rows_html}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <script>
            function toggleCode(idx) {{
                var element = document.getElementById("code-" + idx);
                if (element.style.display === "none") {{
                    element.style.display = "block";
                }} else {{
                    element.style.display = "none";
                }}
            }}

            function filterSeverity() {{
                var selected = document.getElementById("severity-filter").value;
                var rows = document.querySelectorAll(".issue-row");
                rows.forEach(function(row) {{
                    var severity = row.getAttribute("data-severity");
                    if (selected === "ALL" || severity === selected) {{
                        row.style.display = "";
                    }} else {{
                        row.style.display = "none";
                    }}
                }});
            }}
        </script>
    </body>
    </html>
    """
    
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

def execute_scan_task(owner, repo_name, clone_url, branch, sha, pusher_email):
    """
    Ejecuta el clonado y análisis de Trivy y Semgrep en segundo plano.
    Maneja nomenclatura de archivo incluyendo el owner para evitar colisiones.
    """
    print(f"[{datetime.now()}] Iniciando escaneo asíncrono para {owner}/{repo_name} ({branch}) con commit {sha}...")
    
    # 1. Enviar estado PENDING a Gitea
    post_gitea_status(owner, repo_name, sha, "security/semgrep", "pending", "Ejecutando escaneo SAST de Semgrep...")
    post_gitea_status(owner, repo_name, sha, "security/trivy", "pending", "Ejecutando escaneo de vulnerabilidades/secretos...")

    # Ruta del clon temporal
    local_scan_folder = f"{owner}_{repo_name}_{branch}"
    scan_path_in_container = os.path.join(SCANS_DIR, local_scan_folder)
    host_scan_path = os.path.join(HOST_SCANS_DIR, local_scan_folder)

    # Eliminar escaneos previos en la misma ruta si existen
    if os.path.exists(scan_path_in_container):
        shutil.rmtree(scan_path_in_container)

    try:
        # Clonar el código del repositorio Gitea
        print(f"Clonando {clone_url} a {scan_path_in_container}...")
        subprocess.run(["git", "clone", "-b", branch, clone_url, scan_path_in_container], check=True)

        os.makedirs(HTML_DIR, exist_ok=True)

        # ------------------
        # 1. EJECUTAR SEMGREP
        # ------------------
        print("Iniciando escaneo con Semgrep...")
        semgrep_json_filename = f"{owner}-{repo_name}-{branch}-semgrep.json"
        semgrep_json_path = os.path.join(scan_path_in_container, semgrep_json_filename)
        semgrep_html_filename = f"{owner}-{repo_name}-{branch}-semgrep.html"
        semgrep_html_path = os.path.join(HTML_DIR, semgrep_html_filename)
        target_url_semgrep = f"{EXTERNAL_REPORTS_URL}/{semgrep_html_filename}"

        # Ejecutamos semgrep
        subprocess.run([
            "docker", "run", "--rm",
            "-v", f"{host_scan_path}:/src",
            "returntocorp/semgrep",
            "semgrep", "scan", "--config=auto", "--json", "-o", f"/src/{semgrep_json_filename}"
        ], check=False)

        # Convertir JSON de Semgrep a HTML y contar incidencias
        semgrep_findings = 0
        if os.path.exists(semgrep_json_path):
            with open(semgrep_json_path, "r", encoding="utf-8") as sj:
                try:
                    semgrep_data = json.load(sj)
                    semgrep_findings = len(semgrep_data.get("results", []))
                    generate_semgrep_html(semgrep_data, semgrep_html_path, repo_name, branch)
                    print(f"Reporte Semgrep HTML generado en {semgrep_html_path}.")
                except Exception as ex_json:
                    print(f"Error al analizar JSON de Semgrep: {ex_json}")
                    post_gitea_status(owner, repo_name, sha, "security/semgrep", "error", f"Error al procesar JSON de Semgrep: {str(ex_json)[:80]}")
        else:
            print("No se generó el archivo JSON de resultados de Semgrep.")
            post_gitea_status(owner, repo_name, sha, "security/semgrep", "error", "No se generaron resultados de Semgrep.")

        # Enviar estado final de Semgrep a Gitea
        if os.path.exists(semgrep_html_path):
            if semgrep_findings > 0:
                post_gitea_status(owner, repo_name, sha, "security/semgrep", "failure", f"Se encontraron {semgrep_findings} fallos de seguridad.", target_url_semgrep)
            else:
                post_gitea_status(owner, repo_name, sha, "security/semgrep", "success", "Análisis completado sin fallos.", target_url_semgrep)

        # ------------------
        # 2. EJECUTAR TRIVY
        # ------------------
        print("Iniciando escaneo con Trivy...")
        trivy_json_filename = f"{owner}-{repo_name}-{branch}-trivy.json"
        trivy_json_path = os.path.join(scan_path_in_container, trivy_json_filename)
        trivy_html_filename = f"{owner}-{repo_name}-{branch}-trivy.html"
        trivy_html_path = os.path.join(HTML_DIR, trivy_html_filename)
        target_url_trivy = f"{EXTERNAL_REPORTS_URL}/{trivy_html_filename}"

        # Ejecutamos Trivy JSON
        subprocess.run([
            "docker", "run", "--rm",
            "-v", f"{host_scan_path}:/apps",
            "-v", "trivy-cache:/root/.cache",
            "aquasec/trivy:latest",
            "fs", "--format", "json", "-o", f"/apps/{trivy_json_filename}", "/apps"
        ], check=False)

        trivy_vulns = 0
        if os.path.exists(trivy_json_path):
            try:
                with open(trivy_json_path, "r", encoding="utf-8") as tj:
                    trivy_data = json.load(tj)
                    for result in trivy_data.get("Results", []):
                        trivy_vulns += len(result.get("Vulnerabilities", []))
                        trivy_vulns += len(result.get("Secrets", []))
            except Exception as ex_tjson:
                print(f"Error al parsear JSON de Trivy: {ex_tjson}")

        # Ejecutamos Trivy HTML
        subprocess.run([
            "docker", "run", "--rm",
            "-v", f"{host_scan_path}:/apps",
            "-v", "trivy-cache:/root/.cache",
            "aquasec/trivy:latest",
            "fs", "--format", "template", "--template", "@contrib/html.tpl", "-o", f"/apps/{trivy_html_filename}", "/apps"
        ], check=False)

        # Mover reporte HTML de Trivy
        trivy_source_html = os.path.join(scan_path_in_container, trivy_html_filename)
        if os.path.exists(trivy_source_html):
            shutil.move(trivy_source_html, trivy_html_path)
            print(f"Reporte Trivy HTML guardado en {trivy_html_path}.")
        else:
            print("No se generó el reporte HTML de Trivy.")

        # Enviar estado final de Trivy a Gitea
        if os.path.exists(trivy_html_path):
            if trivy_vulns > 0:
                post_gitea_status(owner, repo_name, sha, "security/trivy", "failure", f"Trivy detectó {trivy_vulns} vulnerabilidades/secretos.", target_url_trivy)
            else:
                post_gitea_status(owner, repo_name, sha, "security/trivy", "success", "Análisis completado sin vulnerabilidades.", target_url_trivy)
        else:
            post_gitea_status(owner, repo_name, sha, "security/trivy", "error", "No se generó reporte de Trivy.")

        # Actualizar index.html
        generate_index_html()

        # ------------------
        # 3. ENVIAR CORREO
        # ------------------
        if pusher_email:
            send_email_report(
                to_email=pusher_email,
                repo_name=repo_name,
                branch=branch,
                semgrep_count=semgrep_findings,
                trivy_count=trivy_vulns,
                semgrep_path=semgrep_html_path,
                trivy_path=trivy_html_path
            )

        print(f"[{datetime.now()}] Escaneo asíncrono para {owner}/{repo_name} ({branch}) finalizado con éxito.")

    except Exception as e:
        print(f"Error general en el proceso de escaneo asíncrono: {e}")
        post_gitea_status(owner, repo_name, sha, "security/semgrep", "error", f"Error en pipeline: {str(e)[:80]}")
        post_gitea_status(owner, repo_name, sha, "security/trivy", "error", f"Error en pipeline: {str(e)[:80]}")
    finally:
        if os.path.exists(scan_path_in_container):
            shutil.rmtree(scan_path_in_container)

@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.json
    if not data:
        return jsonify({"error": "No data received"}), 400

    # Extraer información del repositorio y evento push
    repo_name = data.get('repository', {}).get('name')
    clone_url = data.get('repository', {}).get('clone_url')
    ref = data.get('ref', 'refs/heads/main')
    branch = ref.split('/')[-1]
    
    owner = data.get('repository', {}).get('owner', {}).get('username')
    if not owner:
        owner = data.get('repository', {}).get('owner', {}).get('login', 'gitea_admin')

    sha = data.get('after')

    # Obtener el correo del desarrollador que hizo push
    pusher_email = data.get('pusher', {}).get('email')
    if not pusher_email and data.get('commits'):
        pusher_email = data.get('commits', [{}])[-1].get('author', {}).get('email')
    if not pusher_email:
        pusher_email = "admin@example.com"

    # Reemplazar localhost en la URL de clonación para usar la red interna de Docker
    if clone_url:
        clone_url = clone_url.replace("localhost:3000", "gitea-server:3000")
        clone_url = clone_url.replace("127.0.0.1:3000", "gitea-server:3000")

    if not repo_name or not clone_url:
        return jsonify({"error": "Invalid repository details"}), 400

    # Iniciar la tarea de escaneo en un hilo de fondo (asíncrono)
    thread = threading.Thread(target=execute_scan_task, args=(owner, repo_name, clone_url, branch, sha, pusher_email))
    thread.start()

    return jsonify({
        "status": "accepted", 
        "message": f"Escaneo del commit {sha} en rama {branch} iniciado en segundo plano."
    }), 202

def generate_index_html():
    """
    Genera un index.html dinámico que lista todos los reportes de ramas disponibles.
    """
    files = os.listdir(HTML_DIR)
    
    # Encontrar las ramas escaneadas agrupadas por repositorio
    # Formato de archivo: {owner}-{repo_name}-{branch}-semgrep.html
    repo_branch_map = {} # { owner/repo: { branch: { semgrep_link, trivy_link } } }
    
    for f in files:
        if f.endswith("-semgrep.html") or f.endswith("-trivy.html"):
            is_semgrep = f.endswith("-semgrep.html")
            base = f.replace("-semgrep.html", "").replace("-trivy.html", "")
            
            # Separar owner, repo, y branch
            parts = base.split('-')
            if len(parts) >= 3:
                owner = parts[0]
                repo = parts[1]
                branch = "-".join(parts[2:])
                full_repo_name = f"{owner}/{repo}"
            elif len(parts) == 2:
                repo = parts[0]
                branch = parts[1]
                full_repo_name = repo
            else:
                repo = base
                branch = "main"
                full_repo_name = repo

            if full_repo_name not in repo_branch_map:
                repo_branch_map[full_repo_name] = {}
            if branch not in repo_branch_map[full_repo_name]:
                repo_branch_map[full_repo_name][branch] = {"semgrep": None, "trivy": None}
                
            if is_semgrep:
                repo_branch_map[full_repo_name][branch]["semgrep"] = f
            else:
                repo_branch_map[full_repo_name][branch]["trivy"] = f

    list_items = ""
    for repo, branches in sorted(repo_branch_map.items()):
        list_items += f"""
        <div class="col-12 mb-4">
            <div class="card bg-secondary text-white border-0 shadow">
                <div class="card-body">
                    <h5 class="card-title fw-bold">📦 Repositorio: {repo}</h5>
                    <div class="table-responsive mt-3">
                        <table class="table table-dark table-hover align-middle">
                            <thead>
                                <tr>
                                    <th>Rama</th>
                                    <th>Reporte Semgrep (SAST)</th>
                                    <th>Reporte Trivy (Vulnerabilidades)</th>
                                </tr>
                            </thead>
                            <tbody>
        """
        for branch, links in sorted(branches.items()):
            semgrep_link = links["semgrep"]
            trivy_link = links["trivy"]
            
            list_items += f"""
                                <tr>
                                    <td><span class="badge bg-dark px-3 py-2">{branch}</span></td>
                                    <td>
                                        {f'<a href="{semgrep_link}" class="btn btn-primary btn-sm" target="_blank">🔍 Ver Reporte</a>' if semgrep_link else '<span class="text-muted">No generado</span>'}
                                    </td>
                                    <td>
                                        {f'<a href="{trivy_link}" class="btn btn-warning text-dark btn-sm fw-bold" target="_blank">🛡️ Ver Reporte</a>' if trivy_link else '<span class="text-muted">No generado</span>'}
                                    </td>
                                </tr>
            """
        list_items += """
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
        """

    if not repo_branch_map:
        list_items = """
        <div class="col-12 text-center text-muted py-5">
            <h3>Aún no se han generado reportes de escaneo.</h3>
            <p>Sube código a tu repositorio de Gitea para iniciar los escaneos automatizados.</p>
        </div>
        """

    index_content = f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Dashboard de Reportes de Seguridad</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {{
                background-color: #0f172a;
                color: #e2e8f0;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }}
            .jumbotron {{
                background: linear-gradient(135deg, #1e293b, #0f172a);
                border-radius: 16px;
                padding: 40px;
                border: 1px solid #334155;
            }}
            .table {{
                margin-bottom: 0;
            }}
        </style>
    </head>
    <body>
        <div class="container py-5">
            <div class="jumbotron mb-5 text-center text-md-start">
                <h1 class="display-5 fw-bold text-white mb-3">🛡️ Security Scan Portal</h1>
                <p class="lead text-muted">Portal interno de visualización de vulnerabilidades para Gitea local.</p>
                <hr class="my-4 border-secondary">
                <p>Cada vez que un desarrollador hace <code>git push</code>, el sistema de Webhooks ejecuta automáticamente Trivy y Semgrep para detectar brechas de seguridad.</p>
            </div>

            <h3 class="mb-4 fw-bold">Reportes de Seguridad por Rama</h3>
            <div class="row">
                {list_items}
            </div>
        </div>
    </body>
    </html>
    """
    
    with open(os.path.join(HTML_DIR, "index.html"), "w", encoding="utf-8") as f:
        f.write(index_content)

if __name__ == '__main__':
    os.makedirs(HTML_DIR, exist_ok=True)
    os.makedirs(SCANS_DIR, exist_ok=True)
    generate_index_html()
    app.run(host='0.0.0.0', port=5000)
