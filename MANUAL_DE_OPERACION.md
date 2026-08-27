# Manual de Operación y Guía Técnica: Portal Central de Escaneo de Código (SCAN-CODE)

**Versión del Documento:** 2.2  
**Fecha de Actualización:** Agosto 2026  
**Sistema:** SCAN-CODE Central Security Scanner  
**Audiencia:** Operadores de Ciberseguridad, Administradores DevSecOps, Desarrolladores y Auditores  

---

## 📋 Índice de Contenidos
1. [Visión General y Arquitectura Técnica](#1-visión-general-y-arquitectura-técnica)
2. [¿Qué hace Técnicamente el Sistema? (Motores SAST y SCA)](#2-qué-hace-técnicamente-el-sistema-motores-sast-y-sca)
3. [Integración con Servidores GitLab](#3-integración-con-servidores-gitlab)
4. [Procedimientos de Escaneo de Código](#4-procedimientos-de-escaneo-de-código)
5. [Guía de Uso de la Interfaz Web](#5-guía-de-uso-de-la-interfaz-web)
6. [Flujo de Trabajo Operativo (Ciclo de Vida de una Vulnerabilidad)](#6-flujo-de-trabajo-operativo-ciclo-de-vida-de-una-vulnerabilidad)
7. [Administración de Usuarios y Autenticación LDAP](#7-administración-de-usuarios-y-autenticación-ldap)
8. [Mantenimiento, Comandos de Soporte y Diagnóstico](#8-mantenimiento-comandos-de-soporte-y-diagnóstico)

---

## 1. Visión General y Arquitectura Técnica

El **Portal Central de Escaneo de Código (SCAN-CODE)** es una solución integral diseñada para centralizar, automatizar y gobernar la seguridad del código fuente y de la cadena de suministro de software de toda la organización.

```mermaid
flowchart TD
    subgraph Servidor Central ["Servidor Central SCAN-CODE (172.27.103.42)"]
        WEB["Servidor Web Flask (HTTPS :5000)"]
        DB[(PostgreSQL 'scancode')]
        DAEMON["Demonio Background Scheduler (02:00 AM)"]
        ORCH["Orquestador de Escaneo (scanner.py)"]
        
        subgraph Motores Locales
            SEMGREP["Semgrep CLI (SAST Engine)"]
            TRIVY["Trivy CLI (SCA & Dependencies Engine)"]
        end
    end

    subgraph Infraestructura Corporativa
        GL["GitLab MQuest (192.168.2.121/gitlab)"]
        LDAP["Directorio Activo / LDAP Corporativo"]
    end

    WEB <--> DB
    DAEMON --> ORCH
    WEB --> ORCH
    ORCH --> SEMGREP
    ORCH --> TRIVY
    ORCH <--"REST API v4 / Git Clone (PAT Cifrado)"--> GL
    WEB <--"Autenticación Bind DN"--> LDAP
```

### 📍 Datos de Infraestructura y Despliegue
- **Dirección IP del Servidor:** `172.27.103.42`
- **Ruta de Despliegue:** `/data/central-scanner/`
- **Servicio Systemd:** `central-scanner.service` (Usuario: `mquser`)
- **Base de Datos:** PostgreSQL local (`postgresql://scancode:scancode_pass@localhost:5432/scancode`)
- **Acceso Web Cifrado:** **`https://172.27.103.42:5000/`** (Certificados SSL/TLS RSA-4096)
- **Repositorio de Respaldo:** `https://github.com/cplazaibarra/analisis-codigo`

---

## 2. ¿Qué hace Técnicamente el Sistema? (Motores SAST y SCA)

SCAN-CODE orquesta dos motores de análisis estático instalados a nivel de sistema operativo para auditar el 100% del espectro de seguridad de una aplicación:

```
                               ┌──────────────────────────────────────────────┐
                               │           REPOSITORIO DEL PROYECTO           │
                               └──────────────────────┬───────────────────────┘
                                                      │
                       ┌──────────────────────────────┴──────────────────────────────┐
                       ▼                                                             ▼
         [ CÓDIGO FUENTE PROPIO ]                                      [ DEPENDENCIAS DE TERCEROS ]
         (Archivos .c, .go, .py, .js)                                  (go.mod, requirements.txt, package.json)
                       │                                                             │
                       ▼                                                             ▼
         ┌───────────────────────────┐                                 ┌───────────────────────────┐
         │       SEMGREP (SAST)      │                                 │        TRIVY (SCA)        │
         └─────────────┬─────────────┘                                 └─────────────┬─────────────┘
                       │                                                             │
                       ▼                                                             ▼
         • Análisis Sintáctico AST                                     • Extracción del árbol de módulos
         • Búsqueda de Inyecciones                                     • Cruce con bases NVD/CVE/GitHub
         • Detección de Buffer Overflows                               • Identificación de dependencias transitivas
         • Credenciales quemadas (Secrets)                             • Recomendación exacta de versión segura
```

### A. Semgrep (SAST - Static Application Security Testing)
- **Funcionamiento Técnico:** Analiza el árbol de sintaxis abstracta (*AST - Abstract Syntax Tree*) del código fuente sin necesidad de compilarlo ni ejecutarlo.
- **Lenguajes Soportados:** C, C++, Go, Python, Java, JavaScript, TypeScript, Shell Script, Ruby, PHP.
- **Tipos de Vulnerabilidades Detectadas:**
  - **Manejo Inseguro de Memoria:** Uso de funciones vulnerables a desbordamiento de búfer (`strcpy`, `strcat`, `sprintf`, `gets`).
  - **Inyecciones:** SQL Injection, Command Injection, LDAP Injection, Path Traversal.
  - **Secretos Expuestos:** Claves privadas, tokens JWT, contraseñas y API keys hardcodeadas en texto plano.
  - **Criptografía Débil:** Uso de algoritmos obsoletos (MD5, SHA1, DES, RC4) o generadores aleatorios predecibles.

### B. Trivy (SCA - Software Composition Analysis)
- **Funcionamiento Técnico:** Inspecciona los archivos de manifiesto de librerías y dependencias, mapeando dependencias directas y transitivas contra bases de datos globales de vulnerabilidades (NVD, CVE, GitHub Advisory Database).
- **Ecosistemas Auditados:**
  - **Go:** `go.mod`, `go.sum`
  - **Python:** `requirements.txt`, `Pipfile.lock`, `poetry.lock`
  - **Node.js:** `package.json`, `package-lock.json`, `yarn.lock`
  - **Java:** `pom.xml`, `build.gradle`
  - **C/C++:** Bibliotecas del sistema y paquetes empotrados.
- **Resultado:** Entrega el identificador **CVE**, la severidad del fallo y la **versión exacta de solución** a la que se debe actualizar el paquete.

---

## 3. Integración con Servidores GitLab

SCAN-CODE se conecta de manera desacoplada y segura con instancias de **GitLab Community Edition (CE)** o **GitLab Enterprise Edition (EE)**.

### 🔑 Paso 1: Generación del Token PAT en GitLab
Para que SCAN-CODE pueda listar repositorios y descargar código fuente, se debe crear un **Personal Access Token (PAT)** en GitLab:
1. Iniciar sesión en GitLab (`http://192.168.2.121/gitlab`).
2. Ir a **User Settings ➡️ Access Tokens** (o *Preferences ➡️ Access Tokens*).
3. Asignar un nombre descriptivo: `SCAN-CODE-Agent`.
4. Marcar los siguientes **Scopes (Permisos)**:
   - `read_api` (o `api`): Permite consultar grupos, proyectos y ramas vía REST API.
   - `read_repository`: Permite clonar o descargar el código de los repositorios.
5. Hacer clic en **Create personal access token** y copiar la clave generada (ej: `glpat-a1b2c3d4e5f6g7h8i9j0`).

### ⚙️ Paso 2: Registrar el Servidor GitLab en SCAN-CODE
1. Ingresar al portal SCAN-CODE: **`https://172.27.103.42:5000/`**.
2. En el menú lateral izquierdo, desplegar **Configuración** ➡️ **Integraciones GitLab** (`/settings`).
3. En la tarjeta **Enlazar Nuevo Server GitLab**, completar:
   - **Nombre de la Instancia:** Ej: `GitLab MQuest`.
   - **Dirección IP / URL:** URL base completa de GitLab (ej: `http://192.168.2.121/gitlab`).
   - **Personal Access Token (PAT):** Pegar el token `glpat-...`.
4. Hacer clic en **`Guardar e Intentar Conexión`**.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 🦊 Configuración de Integraciones GitLab                                    │
├─────────────────┬───────────────────────────────┬─────────────────┬─────────┤
│ Instancia       │ URL                           │ Estado Conexión │ Acción  │
├─────────────────┼───────────────────────────────┼─────────────────┼─────────┤
│ GitLab MQuest   │ http://192.168.2.121/gitlab   │ 🟢 Conectado    │ ⚡ Probar│
└─────────────────┴───────────────────────────────┴─────────────────┴─────────┘
```

### 🛡️ Paso 3: Probar y Validar la Conectividad
- Cada servidor registrado cuenta con el botón **`⚡ Probar Conexión`**.
- Al hacer clic, el backend ejecuta una consulta asíncrona a `GET /api/v4/version` de GitLab.
- El sistema confirmará con un banner verde: `✅ ¡Conexión exitosa con la API de GitLab!` sin recargar la página.

> [!TIP]
> **Enmascaramiento de Seguridad:** Los tokens almacenados se muestran con máscara (`glpat-••••••••••••yf1r`) dentro del campo de texto de edición. Si editas el nombre o URL sin tocar el token, el sistema conserva el secreto original sin sobreescribirlo.

---

## 4. Procedimientos de Escaneo de Código

Existen cuatro mecanismos para ejecutar escaneos de seguridad en SCAN-CODE:

```mermaid
graph LR
    A[Opciones de Escaneo] --> B[1. Importación Inicial]
    A --> C[2. Escaneo Individual Manual]
    A --> D[3. Escaneo Global Forzado]
    A --> E[4. Escaneo Automático Nocturno (02:00 AM)]
```

---

### Procedimiento A: Importar y Escanear Nuevos Proyectos desde GitLab
1. En el menú lateral izquierdo, hacer clic en **`📥 Importar`** (`/import`).
2. El sistema consultará la API de GitLab y listará todos los repositorios disponibles agrupados por categoría.
3. Buscar el repositorio deseado y presionar **`➕ Importar y Enlazar`**.
4. El proyecto quedará inmediatamente registrado en la base de datos y disponible en el **Resumen**.

---

### Procedimiento B: Escaneo Manual Individual (Bajo Demanda)
Ideal cuando un desarrollador acaba de subir un commit o corregir un fallo y se desea validar de inmediato:
1. Ir a la pantalla de **`🏠 Resumen`** (`/`).
2. Ubicar la fila del proyecto correspondiente (ej: `mquest / Products / LNP`).
3. Hacer clic en el botón **`▶ Escanear`**.
4. **Comportamiento Técnico:**
   - El botón mostrará un indicador de carga: `⌛ Escaneando...`.
   - SCAN-CODE descarga efímeramente el código del repositorio desde GitLab.
   - Ejecuta **Semgrep** y **Trivy** en paralelo.
   - Reemplaza en la base de datos los hallazgos anteriores por los nuevos resultados.
   - Al finalizar, la fila se actualiza a `🟢 Escaneado`, actualiza la fecha/hora y muestra los nuevos contadores de severidad.

---

### Procedimiento C: Escaneo Automático Diario Programado (02:00 AM)
El sistema incluye un demonio en segundo plano (*Background Thread Scheduler*) para que los proyectos se auditen todas las noches sin intervención humana:

1. Ir a **Configuración** ➡️ **`🗓️ Programación Escaneo`** (`/settings/schedule`).
2. **Activar el interruptor:** `Activar Escaneo Automático Diario` (debe quedar en estado azul activo).
3. **Hora de Ejecución:** Definir la hora en formato 24 horas (por defecto **`02:00`**).
4. Presionar **`💾 Guardar Programación`**.
5. **Comportamiento Automático:**
   - Cada noche a las `02:00 AM`, el demonio recorre todos los proyectos registrados en la base de datos.
   - Extrae el último commit de la rama principal de cada repositorio.
   - Ejecuta el análisis completo SAST y SCA.
   - Actualiza el panel de control para que el equipo comience el día con métricas frescas.

---

### Procedimiento D: Escaneo Global Forzado de Todos los Proyectos
Si se desea ejecutar un barrido completo a todos los proyectos en este instante:
1. Ir a **Configuración** ➡️ **Programación Escaneo**.
2. En la tarjeta lateral **Estado del Planificador**, hacer clic en **`⚡ Ejecutar Escaneo Programado Ahora`**.
3. El sistema ejecutará el análisis secuencial en todos los proyectos y mostrará el mensaje de confirmación al terminar.

---

## 5. Guía de Uso de la Interfaz Web

La interfaz ha sido diseñada con un tema moderno, limpio (*Light Mode*) y un menú lateral oscuro (*Dark Sidebar*) organizado en las siguientes secciones:

```
├── 🏠 Resumen                -> Tablero principal con métricas globales y tabla de proyectos
├── 📥 Importar               -> Catálogo de repositorios GitLab listos para ser enlazados
├── 📄 Reportes               -> Matriz global de todas las vulnerabilidades con filtros y recomendaciones
├── 👥 Usuarios               -> Administración de usuarios locales y enlace a Directorio Activo LDAP
└── ⚙️ Configuración (Menú plegable)
    ├── 🦊 Integraciones GitLab     -> Servidores GitLab, URL y Personal Access Tokens (PAT)
    └── 🗓️ Programación Escaneo     -> Activar/desactivar y programar horario del escaneo nocturno
```

---

### 1. Pantalla de Resumen (`/`)
- **Tarjetas Superiores:**
  - 📁 **Proyectos:** Total de repositorios bajo monitoreo.
  - 🔴 **Críticos / Altos:** Vulnerabilidades de máxima prioridad (requieren atención inmediata).
  - 🟡 **Medios:** Vulnerabilidades de riesgo moderado.
  - 🟢 **Bajos:** Advertencias informativas y buenas prácticas.
- **Tabla de Proyectos Registrados:**
  - Cada fila indica: Nombre del Proyecto, Servidor GitLab de origen, Fecha del último escaneo, Estado (`🟢 Escaneado`), Contadores por color de severidad, Botón **`▶ Escanear`** y Botón **`📊 Ver Reporte`**.

---

### 2. Vista Detallada de Proyecto (`/project/<id>`)
Al presionar **`📊 Ver Reporte`** en cualquier proyecto:
- **Pestañas Superiores de Escáner con Contadores:**
  - `🌐 Todos los Escáneres (Total: X)` *(Muestra ambos motores simultáneamente)*
  - `🔍 Semgrep (SAST) (Total: Y)`
  - `🛡️ Trivy (SCA) (Total: Z)`
- **Filtro de Severidad:** Selector para aislar vulnerabilidades `Crítico / Alto`, `Medio` o `Bajo`.
- **Tabla Consolidada a Ancho Total:**
  - Lista clara con badges de herramienta (`SEMGREP` / `TRIVY`), Severidad, Regla/CVE, Archivo/Línea y el botón **`🔍 Ver`**.

---

### 3. Modal Interactivo de Recomendación y Código
Al presionar el botón **`🔍 Ver`** en cualquier vulnerabilidad de la tabla, se abre una ventana emergente con:
- **Regla / CVE:** Identificador estándar del fallo.
- **Ubicación en Código Fuente:** Archivo exacto (ej. `go-connector/go.mod`) y número de línea.
- **Descripción y Solución:** Explicación técnica clara del problema y recomendación de remediación (ej. *Actualizar librería a versión 0.38.0*).
- **Fragmento de Código Afectado:** Bloque de código fuente con fondo oscuro para inspeccionar la línea vulnerable.

---

## 6. Flujo de Trabajo Operativo (Ciclo de Vida de una Vulnerabilidad)

A continuación se detalla el ciclo completo desde que se detecta un fallo hasta que queda resuelto:

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Desarrollador
    participant GL as GitLab MQuest
    participant SC as Portal SCAN-CODE (HTTPS)
    participant DB as Base de Datos

    Note over SC: 1. Escaneo Nocturno (02:00 AM) o Manual
    SC->>DB: Registra hallazgo: strcpy() inseguro en main.c:42
    
    actor Op as Operador / Auditor
    Op->>SC: Ingresa a /findings y presiona "🔍 Ver"
    SC-->>Op: Modal muestra: "Reemplazar strcpy por strncpy() para evitar Buffer Overflow"
    Op->>Dev: Notifica ticket de corrección con la recomendación exacta
    
    Dev->>Dev: Corrige main.c usando strncpy()
    Dev->>GL: git push origin main
    
    Op->>SC: Presiona "▶ Escanear" en el proyecto
    SC->>GL: Descarga el último commit
    SC->>SC: Ejecuta Semgrep + Trivy
    SC->>DB: Elimina el hallazgo corregido
    Note over SC,DB: El contador de alarmas baja a 0 y el estado queda en verde
```

---

## 7. Administración de Usuarios y Autenticación LDAP

Ubicación: **`👥 Usuarios`** (`/users`) en el menú lateral.

### A. Pestaña 1: Usuarios Locales
- Permite crear cuentas locales con nombre de usuario, correo electrónico, contraseña cifrada con algoritmo PBKDF2/SHA-256 y rol de administrador.
- Permite eliminar operadores que ya no requieran acceso.

### B. Pestaña 2: Autenticación LDAP / Active Directory
Permite autenticar a los ingenieros y operadores directamente contra el Directorio Activo institucional:
- **Activar Autenticación LDAP:** Interruptor general.
- **Servidor LDAP:** `ldap://192.168.x.x` (o `ldaps://...`).
- **Puerto:** `389` (o `636` para SSL).
- **Bind DN & Contraseña:** Credenciales de la cuenta de servicio de lectura.
- **Base de Búsqueda (Search Base):** Ej. `ou=Users,dc=mquest,dc=local`.
- **Filtro de Usuario:** `(uid={username})` o `(sAMAccountName={username})`.
- **Grupo Requerido:** Nombre del grupo de seguridad necesario para acceder (ej. `git` o `sec-team`).

---

## 8. Mantenimiento, Comandos de Soporte y Diagnóstico

### Acceso Administrativo por Terminal SSH
```bash
ssh mquser@172.27.103.42
# Contraseña estándar de mantenimiento
```

### Control del Servicio Web
```bash
# Ver estado del servicio
systemctl --user status central-scanner.service

# Reiniciar el portal web y demonio
systemctl --user restart central-scanner.service

# Detener el servicio
systemctl --user stop central-scanner.service
```

### Inspección de Logs en Tiempo Real
```bash
# Ver los últimos 100 eventos y seguir en vivo
journalctl --user-unit=central-scanner.service -f -n 100
```

### Verificación de Certificados SSL/TLS
```bash
# Verificar archivos de certificado
ls -lh /data/central-scanner/cert.pem /data/central-scanner/key.pem

# Comprobar respuesta HTTPS interna
curl -k -I https://127.0.0.1:5000/login
```

### Verificación de Herramientas de Escaneo en el Servidor
```bash
# Versión de Semgrep SAST
semgrep --version

# Versión de Trivy SCA
trivy --version
```
