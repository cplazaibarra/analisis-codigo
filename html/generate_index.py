import os
import re
import json
from datetime import datetime

HTML_DIR = "/app/html"
REPORTS_DIR = os.path.join(HTML_DIR, "reports")

def generate_semgrep_html(json_data, html_path, repo_name, branch):
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
                margin: 0;
            }}
            .navbar-custom {{
                background-color: #1e293b;
                border-bottom: 1px solid #334155;
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
        <!-- Barra de Navegación con Botón Volver -->
        <nav class="navbar navbar-custom py-3 mb-4">
            <div class="container d-flex justify-content-between align-items-center">
                <a href="/index.html" class="btn btn-outline-info">⬅️ Volver al Dashboard</a>
                <span class="text-white fw-bold">Reporte Semgrep SAST</span>
            </div>
        </nav>

        <div class="container py-2">
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

def inject_trivy_back_button(html_path, repo_name, branch):
    if not os.path.exists(html_path):
        return
        
    try:
        with open(html_path, "r", encoding="utf-8") as f:
            content = f.read()
            
        # Evitar inyección doble
        if "Volver al Dashboard" in content:
            return
            
        # Barra de navegación para Trivy (diseño adaptado al tema claro de Trivy)
        nav_html = f"""
<div style="background-color: #0f172a; color: #f8fafc; padding: 12px 20px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #38bdf8;">
    <a href="/index.html" style="color: #38bdf8; text-decoration: none; font-weight: bold; font-size: 14px; border: 1px solid #38bdf8; padding: 6px 14px; border-radius: 4px; display: inline-flex; align-items: center; transition: all 0.2s;">⬅️ Volver al Dashboard</a>
    <span style="font-weight: bold; font-size: 16px; letter-spacing: 0.5px;">🛡️ Reporte de Vulnerabilidades (Trivy) — {repo_name} ({branch})</span>
</div>
"""
        # Inyectar inmediatamente después del tag <body> (case-insensitive)
        modified_content = re.sub(r'(<body[^>]*>)', r'\1\n' + nav_html, content, flags=re.IGNORECASE, count=1)
        
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(modified_content)
        print(f"Barra de navegación inyectada con éxito en Trivy: {html_path}")
    except Exception as e:
        print(f"Error al inyectar barra en Trivy {html_path}: {e}")

def process_semgrep_json_files():
    if not os.path.exists(REPORTS_DIR):
        return

    for repo in os.listdir(REPORTS_DIR):
        repo_path = os.path.join(REPORTS_DIR, repo)
        if not os.path.isdir(repo_path):
            continue
            
        for branch in os.listdir(repo_path):
            branch_path = os.path.join(repo_path, branch)
            if not os.path.isdir(branch_path):
                continue
                
            json_path = os.path.join(branch_path, "semgrep.json")
            html_path = os.path.join(branch_path, "semgrep.html")
            
            if os.path.exists(json_path):
                print(f"Procesando Semgrep JSON a HTML para: {repo} ({branch})...")
                try:
                    with open(json_path, "r", encoding="utf-8") as sj:
                        semgrep_data = json.load(sj)
                        generate_semgrep_html(semgrep_data, html_path, repo, branch)
                    print(f"Reporte HTML de Semgrep generado en: {html_path}")
                except Exception as e:
                    print(f"Error al procesar JSON {json_path}: {e}")

def process_trivy_html_files():
    if not os.path.exists(REPORTS_DIR):
        return

    # Buscar HTML de Trivy en reports/{repo}/{branch}/trivy.html
    for repo in os.listdir(REPORTS_DIR):
        repo_path = os.path.join(REPORTS_DIR, repo)
        if not os.path.isdir(repo_path):
            continue
            
        for branch in os.listdir(repo_path):
            branch_path = os.path.join(repo_path, branch)
            if not os.path.isdir(branch_path):
                continue
                
            trivy_html = os.path.join(branch_path, "trivy.html")
            if os.path.exists(trivy_html):
                inject_trivy_back_button(trivy_html, repo, branch)

def generate_index_html():
    repo_branch_map = {}
    
    if os.path.exists(REPORTS_DIR):
        for repo in sorted(os.listdir(REPORTS_DIR)):
            repo_path = os.path.join(REPORTS_DIR, repo)
            if not os.path.isdir(repo_path):
                continue
                
            for branch in sorted(os.listdir(repo_path)):
                branch_path = os.path.join(repo_path, branch)
                if not os.path.isdir(branch_path):
                    continue
                
                semgrep_file = "semgrep.html" if os.path.exists(os.path.join(branch_path, "semgrep.html")) else None
                trivy_file = "trivy.html" if os.path.exists(os.path.join(branch_path, "trivy.html")) else None
                
                if semgrep_file or trivy_file:
                    if repo not in repo_branch_map:
                        repo_branch_map[repo] = {}
                    repo_branch_map[repo][branch] = {
                        "semgrep": f"reports/{repo}/{branch}/semgrep.html" if semgrep_file else None,
                        "trivy": f"reports/{repo}/{branch}/trivy.html" if trivy_file else None
                    }

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
                                        {f'<a href="{semgrep_link}" class="btn btn-primary btn-sm">🔍 Ver Reporte</a>' if semgrep_link else '<span class="text-muted">No generado</span>'}
                                    </td>
                                    <td>
                                        {f'<a href="{trivy_link}" class="btn btn-warning text-dark btn-sm fw-bold">🛡️ Ver Reporte</a>' if trivy_link else '<span class="text-muted">No generado</span>'}
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
            <p>Sube código a tus repositorios en GitLab con el archivo .gitlab-ci.yml para iniciar los escaneos automatizados.</p>
        </div>
        """

    index_content = f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Dashboard de Reportes de Seguridad - GitLab</title>
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
                <h1 class="display-5 fw-bold text-white mb-3">🛡️ GitLab Security Scan Portal</h1>
                <p class="lead text-muted">Portal interno de visualización de vulnerabilidades para GitLab CE.</p>
                <hr class="my-4 border-secondary">
                <p>Cada vez que ejecutas un pipeline de CI/CD, Semgrep y Trivy auditan tu código y actualizan este portal dinámicamente.</p>
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
    print("Dashboard index.html generado con éxito.")

if __name__ == '__main__':
    process_semgrep_json_files()
    process_trivy_html_files()
    generate_index_html()
