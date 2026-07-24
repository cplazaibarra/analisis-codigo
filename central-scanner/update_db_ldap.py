from app import app, db, LdapConfig

with app.app_context():
    config = LdapConfig.query.first()
    if not config:
        config = LdapConfig()
        db.session.add(config)
        
    config.enabled = True
    config.server_url = "ldap://192.168.122.151"
    config.port = 389
    config.bind_dn = "cn=admin,dc=mquest,dc=local"
    config.bind_password = "adminpassword"
    config.search_base = "dc=mquest,dc=local"
    config.user_filter = "(uid={username})"
    config.required_group = "git"
    
    db.session.commit()
    print("Base de datos de SCAN-CODE actualizada con la configuración LDAP.")
