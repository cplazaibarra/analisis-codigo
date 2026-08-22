# Manual de Operación: Portal Central de Escaneo de Código (SCAN-CODE)

**Versión del Sistema:** 2.1 (Actualizado con HTTPS, Vista Unificada y Programación Diaria)  
**Fecha:** Agosto 2026  
**Audiencia:** Operadores de Seguridad, Administradores de Infraestructura y Desarrolladores  

---

## 1. Resumen Ejecutivo y Arquitectura del Sistema

El **Portal Central de Escaneo de Código (SCAN-CODE)** es una plataforma de gobierno y auditoría de seguridad que automatiza la inspección de vulnerabilidades en todo el ciclo de vida del desarrollo de software (*SDLC*).

```mermaid
flowchart TD
    subgraph Servidor Central ["Servidor Central (172.27.103.42)"]
        UI["Portal Web Seguro HTTPS Flask (:5000)"]
        DB[(PostgreSQL scancode)]
        SCHED["Demonio de Programación Diaria (02:00 AM)"]
        ENG_SAST["Motor SAST: Semgrep"]
        ENG_SCA["Motor SCA: Trivy"]
    end

    subgraph Integraciones Externas
        GL["GitLab MQuest (192.168.2.121)"]
        LDAP["Directorio LDAP / Active Directory"]
    end

    UI <--> DB
    SCHED --> ENG_SAST
    SCHED --> ENG_SCA
    UI --> ENG_SAST
    UI --> ENG_SCA
    ENG_SAST & ENG_SCA <-- "API REST v4 / Git Clone (PAT Token Seguro)" --> GL
    UI <-- "Autenticación de Usuarios" --> LDAP
```

### 📍 Datos de Instalación y Acceso Seguro
- **Servidor:** `172.27.103.42`
- **Ruta de Instalación:** `/data/central-scanner/`
- **Servicio Systemd:** `central-scanner.service` (Ejecutado bajo el usuario `mquser`)
- **Base de Datos:** PostgreSQL local (`postgresql://scancode:scancode_pass@localhost:5432/scancode`)
- **Protocolo y Acceso Web Seguro:** **`https://172.27.103.42:5000/`** (Cifrado con certificados SSL/TLS RSA-4096).

---

## 2. Conectividad e Integración con GitLab

### 🔗 Protocolo y Autenticación Segura
SCAN-CODE interactúa con la instancia corporativa de GitLab (`http://192.168.2.121/gitlab`) utilizando la **API REST v4**:

1. **Personal Access Token (PAT):**  
   Requiere un token emitido en GitLab con permisos de lectura (`read_api`, `read_repository`).
2. **Protección y Enmascaramiento de Credenciales:**  
   En los formularios y modales de edición, los tokens se almacenan cifrados y se muestran protegidos con máscara (`glpat-••••••••••••yf1r`) dentro del campo de texto. Si el operador no modifica el campo, el token original se mantiene intacto; si escribe un nuevo valor, se actualiza automáticamente.
3. **Prueba de Conexión en Tiempo Real:**  
   Desde **Configuración > Integraciones GitLab**, el botón **`⚡ Probar Conexión`** realiza una llamada asíncrona (AJAX) a `/api/v4/version` para certificar la conexión en tiempo real sin recargar la página.

---

## 3. Motores de Seguridad y Reglas de Análisis

El servidor ejecuta dos motores de escaneo independientes instalados directamente en el sistema operativo base:

| Motor | Tipo de Análisis | ¿Qué analiza? | Ejemplos de Detección |
| :--- | :--- | :--- | :--- |
| **Semgrep** | **SAST** *(Static Application Security Testing)* | Código fuente en C, Go, Python, Java, JavaScript, etc. | Inyecciones SQL/Comandos, llamadas a funciones inseguras de memoria (`strcpy`, `sprintf`), credenciales quemadas (*hardcoded secrets*), desreferencias nulas. |
| **Trivy** | **SCA** *(Software Composition Analysis)* | Archivos de dependencias (`go.mod`, `requirements.txt`, `package.json`, `pom.xml`, etc.). | CVEs públicos conocidos en librerías de terceros y señala la versión exacta de solución para actualizar. |

---

## 4. Flujo Operativo: ¿Qué pasa al hacer un `git push` o corregir código?

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Desarrollador
    participant GL as GitLab MQuest
    participant SC as Portal SCAN-CODE (HTTPS)
    participant DB as Base de Datos PostgreSQL

    Dev->>GL: git push (Sube código corregido o nueva función)
    Note over Dev,GL: La nueva versión del código queda en GitLab
    
    alt Escaneo Manual Inmediato
        actor Op as Operador / Dev
        Op->>SC: Clic en "▶ Escanear" en el proyecto
    else Escaneo Automático Nocturno
        SC->>SC: Demonio ejecuta escaneo a las 02:00 AM
    end

    SC->>GL: Descarga el último commit vía API / Git Clone
    SC->>SC: Ejecuta Semgrep (SAST) + Trivy (SCA)
    SC->>DB: Actualiza la tabla de hallazgos
    Note over SC,DB: Las vulnerabilidades solucionadas desaparecen<br/>Los contadores Crítico/Medio/Bajo disminuyen a cero
    SC-->>Dev: Dashboard actualizado con estado verde y 0 alarmas
```

### 🔄 Ciclo de Vida de una Vulnerabilidad:
1. **Detección Inicial:** El portal detecta un fallo (ej: `strcpy()` inseguro o librería vulnerable `golang.org/x/net v0.2.0`).
2. **Revisión de la Recomendación:** En el portal se hace clic en **`🔍 Ver`** y se revisa la sugerencia técnica de solución (ej: *Actualizar a versión v0.38.0*).
3. **Corrección en Código:** El desarrollador aplica el cambio en su entorno de trabajo y hace `git push` a GitLab.
4. **Validación Automática:** Al pulsar **`▶ Escanear`** (o en el barrido diario de las 02:00 AM), el sistema descarga la nueva versión, confirma la corrección, **elimina la alerta de la base de datos** y reduce el contador de alarmas en el panel.

---

## 5. Programación de Escaneo Automático Diario (02:00 AM)

El sistema cuenta con un demonio interno en segundo plano (*Background Thread Scheduler*):

- **Ruta de Configuración:** `Configuración` ➡️ `Programación Escaneo` (`/settings/schedule`).
- **Hora Predeterminada:** **`02:00` AM** todos los días (configurable en formato 24h).
- **Operación Desatendida:** A la hora fijada, el sistema recorre secuencialmente todos los repositorios registrados, descarga la última versión y re-evalúa todas las vulnerabilidades.
- **Ejecución Forzada:** El botón **`⚡ Ejecutar Escaneo Programado Ahora`** permite forzar un barrido global inmediato de todos los proyectos.

---

## 6. Guía de Uso de la Interfaz Web

```
├── 🏠 Resumen                -> Métricas globales y tabla de proyectos con botón de escaneo
├── 📥 Importar               -> Vinculación de nuevos proyectos desde GitLab
├── 📄 Reportes               -> Matriz de todas las vulnerabilidades con filtros y recomendaciones
├── 👥 Usuarios               -> Gestión de usuarios locales y autenticación LDAP
└── ⚙️ Configuración (Menú desplegable)
    ├── 🦊 Integraciones GitLab     -> Servidores GitLab, URL y Personal Access Tokens (PAT)
    └── 🗓️ Programación Escaneo     -> Interruptor y hora fija del escaneo diario
```

### A. Pantalla de Resumen (`/`)
- **Tarjetas Superiores:** Total de proyectos registrados, total de alarmas Críticas/Altas (rojo), Medias (naranja) y Bajas (verde).
- **Tabla de Proyectos:**
  - **Botón `▶ Escanear`:** Dispara el escaneo individual del proyecto en tiempo real.
  - **Botón `📊 Ver Reporte`:** Abre el desglose consolidado del proyecto (`/project/<id>`).

### B. Vista de Detalle de Proyecto (`/project/<id>`)
- **Filtros por Escáner con Contadores:**
  - `🌐 Todos los Escáneres (Total: X)` *(Vista simultánea por defecto)*
  - `🔍 Semgrep (SAST) (Total: Y)`
  - `🛡️ Trivy (SCA) (Total: Z)`
- **Filtro de Severidad:** Desplegable para aislar fallos `Críticos / Altos`, `Medios` o `Bajos`.
- **Tabla Única Consolidada:** Lista completa con Herramienta, Severidad, Regla/CVE, Archivo/Línea y botón **`🔍 Ver`**.

### C. Reportes Globales (`/findings`)
- Permite filtrar por Proyecto, Severidad y Escáner en todos los repositorios.
- Cada fila incluye el botón **`🔍 Ver`**, que abre un modal con la regla, archivo, línea, fragmento de código y recomendación de solución.

### D. Gestión de Usuarios (`/users`)
- **Pestaña 1 (Usuarios Locales):** Creación y administración de operadores locales.
- **Pestaña 2 (Autenticación LDAP):** Configuración de enlace con Directorio Activo (`ldap://ip:389`, Search Base, Bind DN, filtro de grupo requerido).

---

## 7. Mantenimiento y Comandos de Soporte para Operadores

Acceso por terminal SSH al servidor:
```bash
ssh mquser@172.27.103.42
```

### Comandos de Operación:
```bash
# Ver estado del servicio
systemctl --user status central-scanner.service

# Reiniciar la aplicación
systemctl --user restart central-scanner.service

# Ver logs en vivo en tiempo real
journalctl --user-unit=central-scanner.service -f -n 50
```

### Verificación de Certificados SSL:
```bash
# Certificado y llave privada ubicados en:
ls -la /data/central-scanner/cert.pem /data/central-scanner/key.pem
```
