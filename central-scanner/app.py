from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import datetime
from scanner import scan_project_repository

app = Flask(__name__)
app.secret_key = "scan_code_central_key_123"
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://scancode:scancode_pass@localhost:5432/scancode'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- MODELOS DE BASE DE DATOS ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=True) # None para LDAP
    email = db.Column(db.String(255))
    auth_source = db.Column(db.String(50), default="local") # local, ldap
    is_admin = db.Column(db.Boolean, default=False)

class LdapConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    enabled = db.Column(db.Boolean, default=False)
    server_url = db.Column(db.String(255), nullable=False) # ej: ldap://127.0.0.1
    port = db.Column(db.Integer, default=389)
    bind_dn = db.Column(db.String(255))
    bind_password = db.Column(db.String(255))
    search_base = db.Column(db.String(255))
    user_filter = db.Column(db.String(255), default="(uid={username})")
    required_group = db.Column(db.String(255), default="git")


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

class ScanSchedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    enabled = db.Column(db.Boolean, default=False)
    execution_time = db.Column(db.String(10), default="02:00")
    last_run = db.Column(db.String(50))
    status = db.Column(db.String(255), default="Esperando horario programado")


# --- RUTAS DE LA APLICACIÓN ---

# Helper: Autenticación LDAP con validación de grupo
def authenticate_ldap(username, password, config):
    try:
        import ldap3
        server = ldap3.Server(config.server_url, port=config.port, use_ssl=False, get_info=ldap3.ALL, connect_timeout=5)
        conn = ldap3.Connection(server, user=config.bind_dn, password=config.bind_password, auto_bind=True)
        
        search_filter = config.user_filter.replace('{username}', username)
        conn.search(
            search_base=config.search_base,
            search_filter=search_filter,
            attributes=['mail', 'cn', 'gidNumber']
        )
        
        if not conn.entries:
            return False, "Usuario no encontrado en el directorio LDAP"
            
        user_dn = conn.entries[0].entry_dn
        email = str(conn.entries[0].mail) if 'mail' in conn.entries[0] else f"{username}@ldap.local"
        user_gid = str(conn.entries[0].gidNumber) if 'gidNumber' in conn.entries[0] else None
        
        # Validar pertenencia al grupo requerido si está configurado
        if config.required_group:
            group_name = config.required_group
            if ',' in group_name:
                for part in group_name.split(','):
                    if part.lower().startswith('cn='):
                        group_name = part.split('=')[1]
                        break
            
            group_filter = f"(cn={group_name})"
            conn.search(
                search_base=config.search_base,
                search_filter=group_filter,
                attributes=['member', 'uniqueMember', 'memberUid', 'gidNumber']
            )
            is_member = False
            for entry in conn.entries:
                # Comprobar si es su grupo primario
                if 'gidNumber' in entry and user_gid and str(entry.gidNumber) == user_gid:
                    is_member = True
                    break
                
                members = []
                if 'member' in entry:
                    members.extend([str(m).lower() for m in entry.member])
                if 'uniqueMember' in entry:
                    members.extend([str(m).lower() for m in entry.uniqueMember])
                if 'memberUid' in entry:
                    members.extend([str(m).lower() for m in entry.memberUid])
                
                if user_dn.lower() in members or username.lower() in members:
                    is_member = True
                    break
            
            # Segunda comprobación: buscar en memberOf del usuario
            if not is_member:
                try:
                    conn.search(search_base=user_dn, search_filter="(objectClass=*)", attributes=['memberOf'])
                    if conn.entries and 'memberOf' in conn.entries[0]:
                        group_dns = [str(g).lower() for g in conn.entries[0].memberOf]
                        for g_dn in group_dns:
                            if config.required_group.lower() in g_dn:
                                is_member = True
                                break
                except Exception:
                    pass
            
            if not is_member:
                return False, f"El usuario no pertenece al grupo de LDAP requerido: '{config.required_group}'"
        
        user_conn = ldap3.Connection(server, user=user_dn, password=password)
        if user_conn.bind():
            return True, email
        else:
            return False, "Contraseña de LDAP incorrecta"
    except Exception as e:
        return False, f"Error en conexión LDAP: {str(e)}"

# Hook: Requerir Login en rutas protegidas
@app.before_request
def require_login():
    allowed_endpoints = ['login', 'static', 'api_findings', 'api_test_integration', 'test_integration']
    if request.endpoint in allowed_endpoints:
        return
    if not session.get('user_id'):
        if request.path.startswith('/static/'):
            return
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('user_id'):
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        # 1. Intentar autenticación local
        if user and user.auth_source == 'local':
            if check_password_hash(user.password_hash, password):
                session['user_id'] = user.id
                session['username'] = user.username
                session['is_admin'] = user.is_admin
                flash("Sesión iniciada correctamente", "success")
                return redirect(url_for('index'))
            else:
                flash("Contraseña incorrecta", "danger")
                return render_template('login.html')
        
        # 2. Intentar autenticación LDAP
        ldap_config = LdapConfig.query.first()
        if ldap_config and ldap_config.enabled:
            success, result = authenticate_ldap(username, password, ldap_config)
            if success:
                if not user:
                    user = User(
                        username=username,
                        auth_source='ldap',
                        email=result,
                        is_admin=False
                    )
                    db.session.add(user)
                    db.session.commit()
                
                session['user_id'] = user.id
                session['username'] = user.username
                session['is_admin'] = user.is_admin
                flash("Sesión iniciada correctamente vía LDAP", "success")
                return redirect(url_for('index'))
            else:
                flash(f"Error de autenticación: {result}", "danger")
                return render_template('login.html')
                
        flash("Usuario no encontrado o autenticación fallida", "danger")
        
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Sesión cerrada con éxito", "info")
    return redirect(url_for('login'))


@app.route('/users')
@app.route('/settings/users')
def users_page():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    users = User.query.all()
    ldap_config = LdapConfig.query.first()
    if not ldap_config:
        ldap_config = LdapConfig()
        db.session.add(ldap_config)
        db.session.commit()
    return render_template('users.html', users=users, ldap_config=ldap_config)

@app.route('/settings/ldap/update', methods=['POST'])

@app.route('/ldap')
@app.route('/settings/ldap')
def ldap_settings():
    config = LdapConfig.query.first()
    if not config:
        config = LdapConfig()
        db.session.add(config)
        db.session.commit()
    return render_template('ldap.html', ldap_config=config)

@app.route('/settings/ldap/update', methods=['POST'])
def update_ldap_config():
    if not session.get('is_admin'):
        flash("Solo administradores pueden realizar esta acción", "danger")
        return redirect(url_for('users_page'))
        
    config = LdapConfig.query.first()
    if not config:
        config = LdapConfig()
        db.session.add(config)
        
    config.enabled = 'enabled' in request.form
    config.server_url = request.form.get('server_url')
    config.port = int(request.form.get('port', 389))
    config.bind_dn = request.form.get('bind_dn')
    
    new_bind_password = request.form.get('bind_password')
    if new_bind_password and new_bind_password != '********':
        config.bind_password = new_bind_password
        
    config.search_base = request.form.get('search_base')
    config.user_filter = request.form.get('user_filter', '(uid={username})')
    config.required_group = request.form.get('required_group')
    
    db.session.commit()
    flash("Configuración LDAP guardada con éxito", "success")
    return redirect(url_for('users_page'))

@app.route('/settings/user/add', methods=['POST'])
def add_local_user():
    if not session.get('is_admin'):
        flash("Solo administradores pueden realizar esta acción", "danger")
        return redirect(url_for('users_page'))
        
    username = request.form.get('username')
    password = request.form.get('password')
    email = request.form.get('email')
    is_admin = 'is_admin' in request.form
    
    if not username or not password:
        flash("Usuario y contraseña son obligatorios", "danger")
        return redirect(url_for('users_page'))
        
    if User.query.filter_by(username=username).first():
        flash("El nombre de usuario ya está registrado", "danger")
        return redirect(url_for('users_page'))
        
    new_user = User(
        username=username,
        password_hash=generate_password_hash(password),
        email=email,
        auth_source='local',
        is_admin=is_admin
    )
    db.session.add(new_user)
    db.session.commit()
    flash(f"Usuario {username} creado con éxito", "success")
    return redirect(url_for('users_page'))

@app.route('/settings/user/delete/<int:id>', methods=['POST'])
def delete_local_user(id):
    if not session.get('is_admin'):
        flash("Solo administradores pueden realizar esta acción", "danger")
        return redirect(url_for('users_page'))
        
    user = User.query.get_or_404(id)
    if user.id == session.get('user_id'):
        flash("No puedes eliminar tu propio usuario administrador", "danger")
        return redirect(url_for('users_page'))
        
    db.session.delete(user)
    db.session.commit()
    flash("Usuario eliminado", "info")
    return redirect(url_for('users_page'))

@app.route('/findings')
def view_findings():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    project_id = request.args.get('project_id', type=int)
    severity = request.args.get('severity')
    scanner = request.args.get('scanner')

    query = Finding.query

    if project_id:
        query = query.filter_by(project_id=project_id)
    if severity:
        if severity == 'HIGH':
            query = query.filter(Finding.severity.in_(['HIGH', 'CRITICAL', 'ERROR']))
        elif severity == 'MEDIUM':
            query = query.filter(Finding.severity.in_(['MEDIUM', 'WARNING']))
        elif severity == 'LOW':
            query = query.filter(Finding.severity.in_(['LOW', 'INFO', 'NOTE']))
        else:
            query = query.filter_by(severity=severity)
    if scanner:
        query = query.filter_by(scanner=scanner)

    findings = query.order_by(Finding.id.desc()).all()
    projects = Project.query.all()

    return render_template('findings.html', 
                           findings=findings, 
                           projects=projects,
                           selected_project=project_id,
                           selected_severity=severity,
                           selected_scanner=scanner)

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
    users = User.query.all()
    ldap_config = LdapConfig.query.first()
    return render_template('settings.html', 
                           integrations=integrations,
                           users=users,
                           ldap_config=ldap_config)

@app.route('/settings/integration/add', methods=['POST'])
def add_integration():
    name = request.form.get('name')
    url = request.form.get('url').rstrip('/')
    token = request.form.get('token')
    
    if not name or not url or not token:
        flash("Todos los campos son obligatorios", "danger")
        return redirect(url_for('users_page'))
        
    integration = GitLabIntegration(name=name, url=url, token=token)
    db.session.add(integration)
    db.session.commit()
    
    # Test conexión de inmediato
    test_integration_conn(integration.id)
    
    flash("Instancia de GitLab agregada con éxito", "success")
    return redirect(url_for('users_page'))

@app.route('/settings/integration/edit/<int:id>', methods=['POST'])
def edit_integration(id):
    integration = GitLabIntegration.query.get_or_404(id)
    name = request.form.get('name')
    url = request.form.get('url').rstrip('/')
    token = request.form.get('token')
    
    if not name or not url:
        flash("El nombre y la URL son requeridos", "danger")
        return redirect(url_for('users_page'))
        
    integration.name = name
    integration.url = url
    if token and '••••' not in token and '****' not in token:
        integration.token = token
        
    db.session.commit()
    
    # Test conexión de inmediato
    test_integration_conn(integration.id)
    
    flash("Instancia de GitLab actualizada con éxito", "success")
    return redirect(url_for('users_page'))

@app.route('/settings/integration/delete/<int:id>', methods=['POST'])
def delete_integration(id):
    integration = GitLabIntegration.query.get_or_404(id)
    db.session.delete(integration)
    db.session.commit()
    flash("Instancia de GitLab eliminada", "info")
    return redirect(url_for('users_page'))

@app.route('/settings/integration/test/<int:id>', methods=['POST'])
def test_integration(id):
    status = test_integration_conn(id)
    if status == "Conectado":
        flash("¡Conexión exitosa con la API de GitLab!", "success")
    else:
        flash(f"Error al conectar con GitLab: {status}", "danger")
    return redirect(url_for('users_page'))

def make_gitlab_headers(token):
    """Auto-detect token type: OAuth (64-char hex) uses Bearer, PAT uses PRIVATE-TOKEN."""
    if token and len(token) == 64 and all(c in '0123456789abcdef' for c in token.lower()):
        return {"Authorization": f"Bearer {token}"}
    return {"PRIVATE-TOKEN": token}

def test_integration_conn(integration_id):
    integration = GitLabIntegration.query.get(integration_id)
    try:
        headers = make_gitlab_headers(integration.token)
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


@app.route('/import')
def import_page():
    integrations = GitLabIntegration.query.all()
    if not integrations:
        flash('No hay instancias de GitLab configuradas. Agrega una en Configuración primero.', 'warning')
        return redirect(url_for('users_page'))
    integration_id = request.args.get('integration_id', type=int)
    if not integration_id or not GitLabIntegration.query.get(integration_id):
        integration_id = integrations[0].id
    return redirect(url_for('import_projects_list', id=integration_id))

@app.route('/settings/integration/import/<int:id>')
def import_projects_list(id):
    integration = GitLabIntegration.query.get_or_404(id)
    headers = make_gitlab_headers(integration.token)
    try:
        # Consultar proyectos del servidor GitLab
        response = requests.get(f"{integration.url}/api/v4/projects?membership=true&per_page=100", headers=headers, timeout=5)
        if response.status_code != 200:
            flash(f"Error al obtener proyectos: HTTP {response.status_code}", "danger")
            return redirect(url_for('users_page'))
        
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
        return redirect(url_for('users_page'))

@app.route('/settings/integration/import/<int:id>/save', methods=['POST'])
def save_imported_projects(id):
    integration = GitLabIntegration.query.get_or_404(id)
    selected_project_ids = request.form.getlist('selected_projects')
    
    if not selected_project_ids:
        flash("No seleccionaste ningún proyecto para importar", "warning")
        return redirect(url_for('import_projects_list', id=id))
        
    headers = make_gitlab_headers(integration.token)
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
    severity_filter = request.args.get('severity')

    semgrep_query = Finding.query.filter_by(project_id=id, scanner='semgrep')
    trivy_query = Finding.query.filter_by(project_id=id, scanner='trivy')

    if severity_filter:
        if severity_filter == 'HIGH':
            semgrep_query = semgrep_query.filter(Finding.severity.in_(['HIGH', 'CRITICAL', 'ERROR']))
            trivy_query = trivy_query.filter(Finding.severity.in_(['HIGH', 'CRITICAL', 'ERROR']))
        elif severity_filter == 'MEDIUM':
            semgrep_query = semgrep_query.filter(Finding.severity.in_(['MEDIUM', 'WARNING']))
            trivy_query = trivy_query.filter(Finding.severity.in_(['MEDIUM', 'WARNING']))
        elif severity_filter == 'LOW':
            semgrep_query = semgrep_query.filter(Finding.severity.in_(['LOW', 'INFO', 'NOTE']))
            trivy_query = trivy_query.filter(Finding.severity.in_(['LOW', 'INFO', 'NOTE']))
        else:
            semgrep_query = semgrep_query.filter_by(severity=severity_filter)
            trivy_query = trivy_query.filter_by(severity=severity_filter)

    semgrep_findings = semgrep_query.all()
    trivy_findings = trivy_query.all()

    return render_template('project.html',
                           project=project,
                           semgrep_findings=semgrep_findings,
                           trivy_findings=trivy_findings,
                           selected_severity=severity_filter)

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
    severity = request.args.get('severity')

    query = Finding.query

    if project_id and project_id != 'all':
        query = query.filter_by(project_id=int(project_id))

    if severity and severity != 'all':
        if severity == 'HIGH_CRITICAL':
            query = query.filter(Finding.severity.in_(['HIGH', 'CRITICAL', 'ERROR']))
        elif severity == 'MEDIUM_WARNING':
            query = query.filter(Finding.severity.in_(['MEDIUM', 'WARNING']))
        elif severity == 'LOW_INFO':
            query = query.filter(Finding.severity.in_(['LOW', 'INFO']))
        else:
            query = query.filter(Finding.severity.ilike(severity))

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
            'code_snippet': f.code_snippet
        })

    return jsonify(result)




@app.route('/api/integration/test/<int:id>', methods=['POST'])
def api_test_integration(id):
    try:
        status = test_integration_conn(id)
        if status == 'Conectado':
            return jsonify({'success': True, 'status': status, 'message': '¡Conexión exitosa con la API de GitLab!'})
        else:
            return jsonify({'success': False, 'status': status, 'message': f'Error al conectar con GitLab: {status}'})
    except Exception as e:
        return jsonify({'success': False, 'status': 'Error', 'message': f'Excepción: {str(e)}'})



# --- PROGRAMACIÓN DE ESCANEO AUTOMÁTICO ---

@app.route('/settings/gitlab')
def settings_gitlab():
    return redirect(url_for('settings'))

@app.route('/settings/schedule', methods=['GET', 'POST'])
def schedule_page():
    if not session.get('user_id'):
        return redirect(url_for('login'))

    sched = ScanSchedule.query.first()
    if not sched:
        sched = ScanSchedule(enabled=False, execution_time="02:00", status="Inactivo")
        db.session.add(sched)
        db.session.commit()

    if request.method == 'POST':
        sched.enabled = 'enabled' in request.form
        time_val = request.form.get('execution_time', '02:00')
        sched.execution_time = time_val
        sched.status = "Programado activo" if sched.enabled else "Desactivado"
        db.session.commit()
        flash("Configuración de escaneo programado actualizada con éxito", "success")
        return redirect(url_for('schedule_page'))

    return render_template('schedule.html', sched=sched)

@app.route('/api/schedule/run_now', methods=['POST'])
def run_schedule_now():
    if not session.get('user_id'):
        return jsonify({'success': False, 'message': 'No autorizado'}), 401

    try:
        sched = ScanSchedule.query.first()
        if not sched:
            sched = ScanSchedule(enabled=True, execution_time="02:00")
            db.session.add(sched)

        today_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        sched.last_run = today_str
        sched.status = f"Escaneo manual ejecutado ({today_str})"
        db.session.commit()

        # Trigger scans
        projects = Project.query.all()
        scanned_count = 0
        for p in projects:
            try:
                success, msg, s_f, t_f = scan_project_repository(p.http_url, p.integration.token, p.id)
                if success:
                    scanned_count += 1
            except Exception as e:
                print(f"Error scanning {p.name}: {e}")

        return jsonify({'success': True, 'message': f'¡Escaneo global completado en {scanned_count} proyectos!'})
    except Exception as err:
        return jsonify({'success': False, 'message': f'Error al ejecutar escaneo: {str(err)}'})

import threading, time

def start_scheduler_thread():
    def loop():
        while True:
            try:
                with app.app_context():
                    sched = ScanSchedule.query.first()
                    if sched and sched.enabled:
                        now_str = datetime.datetime.now().strftime("%H:%M")
                        today_str = datetime.datetime.now().strftime("%Y-%m-%d")
                        if now_str == sched.execution_time and (not sched.last_run or not sched.last_run.startswith(today_str)):
                            sched.last_run = f"{today_str} {now_str}"
                            sched.status = f"Escaneo automático en progreso ({now_str})..."
                            db.session.commit()

                            projects = Project.query.all()
                            for p in projects:
                                try:
                                    scan_project_repository(p.http_url, p.integration.token, p.id)
                                except Exception as e:
                                    print(f"Error background scan {p.name}: {e}")

                            sched.status = f"Último escaneo diario exitoso ({today_str} {now_str})"
                            db.session.commit()
            except Exception as ex:
                print(f"Daemon exception: {ex}")
            time.sleep(30)

    t = threading.Thread(target=loop, daemon=True)
    t.start()

start_scheduler_thread()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
