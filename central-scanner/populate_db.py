import datetime
import requests
from app import app, db, GitLabIntegration, Project, Finding
from scanner import scan_project_repository

def main():
    print("=== Central Scanner DB Auto-Population ===")
    with app.app_context():
        # 1. Registrar o actualizar la integración con GitLab
        integration = GitLabIntegration.query.filter_by(name="GitLab HP Local").first()
        if not integration:
            integration = GitLabIntegration(
                name="GitLab HP Local",
                url="http://192.168.122.1:8090",
                token="glpat-MigrationToken12345",
                status="Conectado"
            )
            db.session.add(integration)
            db.session.commit()
            print("🟢 Registro de integración con GitLab creado.")
        else:
            integration.url = "http://192.168.122.1:8090"
            integration.token = "glpat-MigrationToken12345"
            integration.status = "Conectado"
            db.session.commit()
            print("🟢 Integración existente actualizada.")

        # 2. Consultar proyectos remotos de GitLab
        headers = {"PRIVATE-TOKEN": integration.token}
        try:
            print("Obteniendo proyectos desde la API de GitLab...")
            r = requests.get(f"{integration.url}/api/v4/projects?membership=true", headers=headers, timeout=10)
            if r.status_code != 200:
                print(f"❌ Error al consultar la API de GitLab: HTTP {r.status_code}")
                return
            
            gitlab_projects = r.json()
            print(f"Detectados {len(gitlab_projects)} proyectos en GitLab.")
            
            # Importar proyectos si no existen
            for gp in gitlab_projects:
                project = Project.query.filter_by(integration_id=integration.id, gitlab_project_id=gp['id']).first()
                if not project:
                    project = Project(
                        integration_id=integration.id,
                        gitlab_project_id=gp['id'],
                        name=gp['name_with_namespace'],
                        description=gp.get('description', ''),
                        web_url=gp['web_url'],
                        http_url=gp['http_url_to_repo'],
                        status="Pendiente"
                    )
                    db.session.add(project)
                    db.session.commit()
                    print(f"📥 Proyecto importado: {project.name}")
                else:
                    # Actualizar urls si cambiaron
                    project.http_url = gp['http_url_to_repo']
                    db.session.commit()
                    print(f"🔄 Proyecto ya importado: {project.name}")
                    
        except Exception as e:
            print(f"❌ Error al comunicarse con GitLab: {e}")
            return

        # 3. Lanzar escaneo para todos los proyectos
        projects = Project.query.filter_by(integration_id=integration.id).all()
        for p in projects:
            print(f"\n--- Iniciando escaneo de {p.name} ---")
            p.status = "Escaneando"
            db.session.commit()
            
            try:
                success, message, semgrep_findings, trivy_findings = scan_project_repository(
                    repo_url=p.http_url,
                    token=integration.token
                )
                
                if success:
                    # Limpiar hallazgos previos
                    Finding.query.filter_by(project_id=p.id).delete()
                    
                    # Guardar hallazgos Semgrep
                    for sf in semgrep_findings:
                        finding = Finding(
                            project_id=p.id,
                            scanner='semgrep',
                            rule_id=sf['rule_id'],
                            severity=sf['severity'],
                            file_path=sf['file_path'],
                            line_number=sf['line_number'],
                            description=sf['description'],
                            code_snippet=sf['code_snippet'],
                            title=sf['title']
                        )
                        db.session.add(finding)
                        
                    # Guardar hallazgos Trivy
                    for tf in trivy_findings:
                        finding = Finding(
                            project_id=p.id,
                            scanner='trivy',
                            rule_id=tf['rule_id'],
                            severity=tf['severity'],
                            file_path=tf['file_path'],
                            line_number=tf['line_number'],
                            description=tf['description'],
                            code_snippet=tf['code_snippet'],
                            title=tf['title']
                        )
                        db.session.add(finding)
                        
                    p.status = "Escaneado"
                    p.last_scan = datetime.datetime.now()
                    db.session.commit()
                    print(f"✅ Escaneo exitoso para {p.name}. Hallazgos: Semgrep={len(semgrep_findings)}, Trivy={len(trivy_findings)}")
                else:
                    p.status = "Fallido"
                    db.session.commit()
                    print(f"❌ Escaneo fallido para {p.name}: {message}")
                    
            except Exception as e:
                p.status = "Fallido"
                db.session.commit()
                print(f"❌ Error durante el escaneo de {p.name}: {e}")

    print("\n=== Proceso de auto-población finalizado con éxito ===")

if __name__ == "__main__":
    main()
