import ldap3

server_url = "ldap://192.168.122.151:389"
admin_dn = "cn=admin,dc=mquest,dc=local"
admin_password = "adminpassword"

try:
    server = ldap3.Server(server_url)
    conn = ldap3.Connection(server, user=admin_dn, password=admin_password, auto_bind=True)
    
    # 1. Intentar agregar a memberUid (para posixGroup)
    try:
        res = conn.modify("cn=git,ou=groups,dc=mquest,dc=local", {
            'memberUid': [(ldap3.MODIFY_ADD, ['usergit'])]
        })
        print("Modificar memberUid:", res, conn.result)
    except Exception as e:
        print("Fallo modify memberUid:", str(e))
        
    # 2. Intentar agregar a member (para groupOfNames)
    try:
        res = conn.modify("cn=git,ou=groups,dc=mquest,dc=local", {
            'member': [(ldap3.MODIFY_ADD, ['uid=usergit,ou=people,dc=mquest,dc=local'])]
        })
        print("Modificar member DN:", res, conn.result)
    except Exception as e:
        print("Fallo modify member:", str(e))
        
except Exception as e:
    print("Error:", str(e))
