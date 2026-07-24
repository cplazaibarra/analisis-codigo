import ldap3

server_url = "ldap://192.168.122.151:389"
admin_dn = "cn=admin,dc=mquest,dc=local"
admin_password = "adminpassword"

try:
    server = ldap3.Server(server_url)
    conn = ldap3.Connection(server, user=admin_dn, password=admin_password, auto_bind=True)
    
    # 1. Crear el grupo 'git' como posixGroup
    group_dn = "cn=git,ou=groups,dc=mquest,dc=local"
    group_attrs = {
        'objectClass': ['posixGroup', 'top'],
        'cn': 'git',
        'gidNumber': 5000,
        'memberUid': ['usergit']
    }
    
    print("Intentando crear grupo 'git'...")
    if conn.add(group_dn, attributes=group_attrs):
        print("Grupo 'git' creado con éxito.")
    else:
        print("Resultado creación grupo 'git':", conn.result)
        
    # 2. Crear el usuario 'usergit'
    user_dn = "uid=usergit,ou=people,dc=mquest,dc=local"
    user_attrs = {
        'objectClass': ['inetOrgPerson', 'organizationalPerson', 'person', 'top', 'posixAccount'],
        'cn': 'usergit',
        'sn': 'Git User',
        'uid': 'usergit',
        'userPassword': 'user',
        'mail': 'usergit@mquest.local',
        'uidNumber': 10005,
        'gidNumber': 5000,
        'homeDirectory': '/home/usergit',
        'loginShell': '/bin/bash'
    }
    
    print("Intentando crear usuario 'usergit'...")
    if conn.add(user_dn, attributes=user_attrs):
        print("Usuario 'usergit' creado con éxito.")
    else:
        print("Resultado creación usuario 'usergit':", conn.result)
        
except Exception as e:
    print("Error:", str(e))
