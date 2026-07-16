from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
import requests
import datetime
from scanner import scan_project_repository

app = Flask(__name__)
app.secret_key = "scan_code_central_key_123"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scanner.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- MODELOS DE BASE DE DATOS ---

class GitLabIntegration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(255), nullable=False)
    token = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), default="Desconocido") # Conectado, Error, Desconocido

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    integration_id = db.Column(db.Integer, db.ForeignKey('git_lab_integration.id'), nullable=False)
    gitlab_project_id = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    web_url = db.Column(db.String(255))
    http_url = db.Column(db.String(255))
    last_scan = db.Column(db.DateTime)
    status = db.Column(db.String(50), default="Pendiente") # Pendiente, Escaneando, Escaneado, Fallido
    
    integration = db.relationship('GitLabIntegration', backref=db.backref('projects', cascade="all, delete-orphan"))

class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    scanner = db.Column(db.String(50), nullable=False) # semgrep, trivy
    rule_id = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(50), nullable=False) # HIGH, MEDIUM, LOW, CRITICAL
    file_path = db.Column(db.String(255))
    line_number = db.Column(db.Integer)
    description = db.Column(db.Text)
    code_snippet = db.Column(db.Text)
    title = db.Column(db.String(255))
    
    project = db.relationship('Project', backref=db.backref('findings', cascade="all, delete-orphan"))

# --- RUTAS DE LA APLICACIÓN ---

@app.route('/')
def index():
    projects = Project.query.all()
    # Calcular métricas globales
    total_projects = len(projects)
    total_findings = Finding.query.count()
    high_findings = Finding.query.filter(Finding.severity.in_(['HIGH', 'CRITICAL'])).count()
    medium_findings = Finding.query.filter(Finding.severity == 'MEDIUM').count()
    low_findings = Finding.query.filter(Finding.severity == 'LOW').count()
    
    # Detalle de cada proyecto con su cantidad de hallazgos por severidad
    project_list = []
    for p in projects:
        p_high = Finding.query.filter_by(project_id=p.id).filter(Finding.severity.in_(['HIGH', 'CRITICAL'])).count()
        p_medium = Finding.query.filter_by(project_id=p.id).filter_by(severity='MEDIUM').count()
        p_low = Finding.query.filter_by(project_id=p.id).filter_by(severity='LOW').count()
        project_list.append({
            'obj': p,
            'high': p_high,
            'medium': p_medium,
            'low': p_low,
            'total': p_high + p_medium + p_low
        })
        
    # Obtener lista de usuarios/ramas únicas para el filtro
    all_findings = Finding.query.all()
    branches = set()
    for f in all_findings:
        if '.' in f.rule_id:
            branch = f.rule_id.split('.')[-1]
            if branch:
                branches.add(branch)
                
    return render_template('index.html', 
                           projects=project_list, 
                           total_projects=total_projects,
                           total_findings=total_findings,
                           high_findings=high_findings,
                           medium_findings=medium_findings,
                           low_findings=low_findings,
                           branches=sorted(list(branches)),
                           all_projects_list=projects)

@app.route('/settings')
def settings():
    integrations = GitLabIntegration.query.all()
    return render_template('settings.html', integrations=integrations)

@app.route('/settings/integration/add', methods=['POST'])
def add_integration():
    name = request.form.get('name')
    url = request.form.get('url').rstrip('/')
    token = request.form.get('token')
    
    if not name or not url or not token:
        flash("Todos los campos son obligatorios", "danger")
        return redirect(url_for('settings'))
        
    integration = GitLabIntegration(name=name, url=url, token=token)
    db.session.add(integration)
    db.session.commit()
    
    # Test conexión de inmediato
    test_integration_conn(integration.id)
    
    flash("Instancia de GitLab agregada con éxito", "success")
    return redirect(url_for('settings'))

@app.route('/settings/integration/edit/<int:id>', methods=['POST'])
def edit_integration(id):
    integration = GitLabIntegration.query.get_or_404(id)
    name = request.form.get('name')
    url = request.form.get('url').rstrip('/')
    token = request.form.get('token')
    
    if not name or not url:
        flash("El nombre y la URL son requeridos", "danger")
        return redirect(url_for('settings'))
        
    integration.name = name
    integration.url = url
    if token:
        integration.token = token
        
    db.session.commit()
    
    # Test conexión de inmediato
    test_integration_conn(integration.id)
    
    flash("Instancia de GitLab actualizada con éxito", "success")
    return redirect(url_for('settings'))

@app.route('/settings/integration/delete/<int:id>', methods=['POST'])
def delete_integration(id):
    integration = GitLabIntegration.query.get_or_404(id)
    db.session.delete(integration)
    db.session.commit()
    flash("Instancia de GitLab eliminada", "info")
    return redirect(url_for('settings'))

@app.route('/settings/integration/test/<int:id>', methods=['POST'])
def test_integration(id):
    status = test_integration_conn(id)
    if status == "Conectado":
        flash("¡Conexión exitosa con la API de GitLab!", "success")
    else:
        flash(f"Error al conectar con GitLab: {status}", "danger")
    return redirect(url_for('settings'))

def test_integration_conn(integration_id):
    integration = GitLabIntegration.query.get(integration_id)
    try:
        headers = {"PRIVATE-TOKEN": integration.token}
        response = requests.get(f"{integration.url}/api/v4/user", headers=headers, timeout=5)
        if response.status_code == 200:
            integration.status = "Conectado"
            db.session.commit()
            return "Conectado"
        else:
            integration.status = f"Error HTTP {response.status_code}"
            db.session.commit()
            return f"Error HTTP {response.status_code}"
    except Exception as e:
        integration.status = "Error de Red"
        db.session.commit()
        return str(e)

@app.route('/settings/integration/import/<int:id>')
def import_projects_list(id):
    integration = GitLabIntegration.query.get_or_404(id)
    headers = {"PRIVATE-TOKEN": integration.token}
    try:
        # Consultar proyectos del servidor GitLab
        response = requests.get(f"{integration.url}/api/v4/projects?membership=true&per_page=100", headers=headers, timeout=5)
        if response.status_code != 200:
            flash(f"Error al obtener proyectos: HTTP {response.status_code}", "danger")
            return redirect(url_for('settings'))
        
        gitlab_projects = response.json()
        
        # Filtrar cuáles de estos proyectos ya están importados
        imported_ids = [p.gitlab_project_id for p in Project.query.filter_by(integration_id=id).all()]
        
        projects_to_show = []
        for gp in gitlab_projects:
            projects_to_show.append({
                'id': gp['id'],
                'name': gp['name_with_namespace'],
                'web_url': gp['web_url'],
                'http_url': gp['http_url_to_repo'],
                'description': gp.get('description', ''),
                'imported': gp['id'] in imported_ids
            })
            
        return render_template('import.html', integration=integration, projects=projects_to_show)
    except Exception as e:
        flash(f"Error de comunicación con GitLab: {e}", "danger")
        return redirect(url_for('settings'))

@app.route('/settings/integration/import/<int:id>/save', methods=['POST'])
def save_imported_projects(id):
    integration = GitLabIntegration.query.get_or_404(id)
    selected_project_ids = request.form.getlist('selected_projects')
    
    if not selected_project_ids:
        flash("No seleccionaste ningún proyecto para importar", "warning")
        return redirect(url_for('import_projects_list', id=id))
        
    headers = {"PRIVATE-TOKEN": integration.token}
    imported_count = 0
    
    for pid in selected_project_ids:
        # Si ya existe, no duplicar
        exists = Project.query.filter_by(integration_id=id, gitlab_project_id=int(pid)).first()
        if exists:
            continue
            
        # Consultar detalles del proyecto para agregarlo
        response = requests.get(f"{integration.url}/api/v4/projects/{pid}", headers=headers, timeout=5)
        if response.status_code == 200:
            gp = response.json()
            project = Project(
                integration_id=id,
                gitlab_project_id=gp['id'],
                name=gp['name_with_namespace'],
                description=gp.get('description', ''),
                web_url=gp['web_url'],
                http_url=gp['http_url_to_repo'],
                status="Pendiente"
            )
            db.session.add(project)
            imported_count += 1
            
    db.session.commit()
    flash(f"Se importaron {imported_count} proyectos con éxito", "success")
    return redirect(url_for('index'))

@app.route('/project/<int:id>')
def project_detail(id):
    project = Project.query.get_or_404(id)
    semgrep_findings = Finding.query.filter_by(project_id=id, scanner='semgrep').all()
    trivy_findings = Finding.query.filter_by(project_id=id, scanner='trivy').all()
    
    return render_template('project.html', 
                           project=project, 
                           semgrep=semgrep_findings, 
                           trivy=trivy_findings)

@app.route('/scan/<int:id>', methods=['POST'])
def run_scan(id):
    project = Project.query.get_or_404(id)
    project.status = "Escaneando"
    db.session.commit()
    
    try:
        # Ejecutar escaneo local
        success, message, semgrep_findings, trivy_findings = scan_project_repository(
            repo_url=project.http_url,
            token=project.integration.token
        )
        
        if success:
            # Limpiar hallazgos antiguos para este proyecto
            Finding.query.filter_by(project_id=id).delete()
            
            # Registrar nuevos hallazgos Semgrep
            for sf in semgrep_findings:
                finding = Finding(
                    project_id=id,
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
                
            # Registrar nuevos hallazgos Trivy
            for tf in trivy_findings:
                finding = Finding(
                    project_id=id,
                    scanner='trivy',
                    rule_id=tf['rule_id'],
                    severity=tf['severity'],
                    file_path=tf['file_path'],
                    line_number=tf.get('line_number', 0),
                    description=tf['description'],
                    code_snippet=tf.get('code_snippet', ''),
                    title=tf['title']
                )
                db.session.add(finding)
                
            project.status = "Escaneado"
            project.last_scan = datetime.datetime.now()
            db.session.commit()
            return jsonify({'success': True, 'message': 'Escaneo completado exitosamente.'})
        else:
            project.status = "Fallido"
            db.session.commit()
            return jsonify({'success': False, 'message': f'Fallo durante el escaneo: {message}'})
            
    except Exception as e:
        project.status = "Fallido"
        db.session.commit()
        return jsonify({'success': False, 'message': f'Error interno: {str(e)}'})

@app.route('/api/findings')
def get_findings():
    project_id = request.args.get('project_id')
    branch = request.args.get('branch')
    
    query = Finding.query
    
    if project_id and project_id != 'all':
        query = query.filter_by(project_id=int(project_id))
        
    findings = query.all()
    
    result = []
    for f in findings:
        f_branch = f.rule_id.split('.')[-1] if '.' in f.rule_id else 'unknown'
        if branch and branch != 'all' and f_branch != branch:
            continue
            
        result.append({
            'id': f.id,
            'project_name': f.project.name,
            'scanner': f.scanner.upper(),
            'title': f.title,
            'severity': f.severity,
            'file_path': f.file_path,
            'line_number': f.line_number,
            'description': f.description,
            'code_snippet': f.code_snippet,
            'branch': f_branch
        })
        
    return jsonify(result)

@app.route('/project/delete/<int:id>', methods=['POST'])
def delete_project(id):
    project = Project.query.get_or_404(id)
    db.session.delete(project)
    db.session.commit()
    flash("Proyecto removido del portal", "info")
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
