import os
import shutil
import tempfile
import subprocess
import json
import urllib.parse

def get_authenticated_url(repo_url, token):
    # Reemplazar http:// o https:// para inyectar las credenciales oauth2 en la URL de git clone
    parsed = urllib.parse.urlparse(repo_url)
    netloc = parsed.netloc
    if netloc.startswith("localhost:") or netloc == "localhost":
        netloc = netloc.replace("localhost", "192.168.122.1")
    auth_netloc = f"oauth2:{token}@{netloc}"
    return urllib.parse.urlunparse(parsed._replace(netloc=auth_netloc))

def extract_lines(file_path, start_line, end_line):
    # Extraer lineas de código de un archivo de forma segura
    if not os.path.exists(file_path):
        return ""
    try:
        with open(file_path, 'r', errors='ignore') as f:
            lines = f.readlines()
            # lineas son 1-indexed en semgrep
            start = max(0, start_line - 1)
            end = min(len(lines), end_line)
            # Agregar contexto de un par de líneas antes y después si es posible
            context_start = max(0, start - 2)
            context_end = min(len(lines), end + 2)
            
            snippet = []
            for i in range(context_start, context_end):
                prefix = "=> " if i >= start and i < end else "   "
                snippet.append(f"{prefix}{i+1}: {lines[i].rstrip()}")
            return "\n".join(snippet)
    except Exception as e:
        return f"Error al leer fragmento de código: {str(e)}"

def scan_project_repository(repo_url, token):
    temp_dir = tempfile.mkdtemp(prefix="scanner_clone_")
    semgrep_findings = []
    trivy_findings = []
    
    try:
        auth_url = get_authenticated_url(repo_url, token)
        
        # 1. Clonar el repositorio completo (sin --depth 1 para poder listar ramas)
        print(f"Clonando {repo_url} en {temp_dir}...")
        clone_res = subprocess.run(
            ["git", "clone", auth_url, "."],
            cwd=temp_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60
        )
        
        if clone_res.returncode != 0:
            return False, f"Fallo al clonar repositorio: {clone_res.stderr}", [], []
            
        # Obtener lista de ramas remotas
        branches_res = subprocess.run(
            ["git", "branch", "-r"],
            cwd=temp_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10
        )
        
        branches = []
        if branches_res.returncode == 0:
            for line in branches_res.stdout.splitlines():
                if "->" in line:
                    continue
                branch = line.strip().replace("origin/", "")
                if branch and branch not in branches:
                    branches.append(branch)
        
        if not branches:
            branches = ["main"]
            
        print(f"Ramas detectadas para escanear: {branches}")
        
        # Escanear cada rama y agregar los hallazgos
        for branch in branches:
            print(f"Cambiando a rama: {branch}")
            # Checkout con force para limpiar modificaciones previas
            checkout_res = subprocess.run(
                ["git", "checkout", "-f", branch],
                cwd=temp_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=15
            )
            if checkout_res.returncode != 0:
                print(f"Fallo al cambiar a la rama {branch}: {checkout_res.stderr}")
                continue
                
            home_dir = os.path.expanduser("~")
            rules_path = "p/security-audit"
            semgrep_res = subprocess.run(
                ["semgrep", "scan", "--config", rules_path, "--json", "--metrics=on"],
                cwd=temp_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=120
            )
            
            if semgrep_res.returncode in [0, 1]:
                try:
                    data = json.loads(semgrep_res.stdout)
                    for res in data.get('results', []):
                        start_line = res.get('start', {}).get('line', 1)
                        end_line = res.get('end', {}).get('line', start_line)
                        file_path = res.get('path', '')
                        
                        code_snippet = extract_lines(os.path.join(temp_dir, file_path), start_line, end_line)
                        desc_msg = res.get('extra', {}).get('message', '')
                        
                        # Mapear hallazgos de Semgrep agregando tag de usuario/rama
                        semgrep_findings.append({
                            'rule_id': f"{res.get('check_id', 'unknown')}.{branch}",
                            'severity': res.get('extra', {}).get('severity', 'WARNING'),
                            'file_path': file_path,
                            'line_number': start_line,
                            'description': f"[Rama: {branch}] {desc_msg}",
                            'code_snippet': code_snippet,
                            'title': f"{res.get('check_id', 'unknown').split('.')[-1]} ({branch})"
                        })
                except Exception as e:
                    print(f"Error al procesar JSON de Semgrep en rama {branch}: {e}")
            else:
                print(f"Semgrep falló en rama {branch}: {semgrep_res.stderr}")
                
            # 3. Ejecutar Trivy en esta rama
            print(f"Ejecutando Trivy en rama {branch}...")
            trivy_res = subprocess.run(
                ["trivy", "fs", "--format", "json", "."],
                cwd=temp_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=120
            )
            
            if trivy_res.returncode == 0:
                try:
                    data = json.loads(trivy_res.stdout)
                    for result in data.get('Results', []):
                        target_file = result.get('Target', '')
                        
                        for vuln in result.get('Vulnerabilities', []):
                            pkg_name = vuln.get('PkgName', '')
                            installed_ver = vuln.get('InstalledVersion', '')
                            fixed_ver = vuln.get('FixedVersion', 'Ninguna')
                            v_id = vuln.get('VulnerabilityID', 'unknown')
                            
                            code_snippet = ""
                            target_full_path = os.path.join(temp_dir, target_file)
                            if os.path.exists(target_full_path):
                                try:
                                    with open(target_full_path, 'r') as f:
                                        lines = f.readlines()
                                        for idx, line in enumerate(lines):
                                            if pkg_name.lower() in line.lower():
                                                code_snippet = f"   {idx+1}: {line.strip()}"
                                                break
                                except:
                                    pass
                                    
                            trivy_findings.append({
                                'rule_id': f"{v_id}.{branch}",
                                'severity': vuln.get('Severity', 'UNKNOWN'),
                                'file_path': target_file,
                                'line_number': 0,
                                'description': f"[Rama: {branch}] Librería: {pkg_name} ({installed_ver}) -> Solución: {fixed_ver}. {vuln.get('Title', vuln.get('Description', ''))}",
                                'code_snippet': code_snippet,
                                'title': f"{pkg_name} - {v_id} ({branch})"
                            })
                except Exception as e:
                    print(f"Error al procesar JSON de Trivy en rama {branch}: {e}")
            else:
                print(f"Trivy falló en rama {branch}: {trivy_res.stderr}")
                
        return True, "Escaneo completado con éxito.", semgrep_findings, trivy_findings
        
    except Exception as e:
        return False, str(e), [], []
        
    finally:
        # Limpieza del directorio temporal de clonación
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
