# Manual de Operación: Portal Central de Escaneo de Código (SCAN-CODE)

**Versión del Sistema:** 2.0  
**Fecha:** Agosto 2026  
**Destinatarios:** Operadores de Seguridad, Administradores de Infraestructura y Desarrolladores  

---

## 1. Arquitectura y Ubicación del Sistema

El **Portal Central de Escaneo de Código (SCAN-CODE)** es una plataforma web desarrollada en Python (Flask) y PostgreSQL que centraliza la auditoría de seguridad estática (SAST) y análisis de dependencias (SCA) para todos los repositorios corporativos.

```mermaid
flowchart TD
    subgraph Servidor Central ["Servidor Central (172.27.103.42)"]
        UI["Portal Web Flask (:5000)"]
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
    ENG_SAST & ENG_SCA <-- "API v4 / Git Clone (PAT Token)" --> GL
    UI <-- "Autenticación de Usuarios" --> LDAP
```

### 📍 Datos de Instalación
- **Servidor:** `172.27.103.42`
- **Ruta de la Aplicación:** `/data/central-scanner/`
- **Servicio Systemd:** `central-scanner.service` (Ejecutado bajo el usuario `mquser`)
- **Base de Datos:** PostgreSQL local (`postgresql://scancode:scancode_pass@localhost:5432/scancode`)
- **Puerto de Acceso Web:** `http://172.27.103.42:5000/`

---

## 2. Conexión y Comunicación con GitLab

### 🔗 Protocolo y Autenticación
SCAN-CODE se comunica con la instancia de GitLab (`http://192.168.2.121/gitlab`) a través de la **API REST v4**:

1. **Personal Access Token (PAT):**  
   Utiliza un token emitido en GitLab con permisos de lectura (`read_api`, `read_repository`).
2. **Seguridad y Enmascaramiento:**  
   En la interfaz web, el token se almacena cifrado y se muestra protegido con máscara (`glpat-••••••••••••yf1r`) para evitar filtraciones visuales.
3. **Prueba de Conexión en Vivo:**  
   Desde **Configuración > Integraciones GitLab**, el botón **`⚡ Probar Conexión`** realiza una llamada en segundo plano a la API de GitLab (`/api/v4/version`) y actualiza el estado (`🟢 Conectado` / `🔴 Error`) sin recargar la página.

---

## 3. Motores de Seguridad Utilizados

El servidor ejecuta dos motores de escaneo independientes instalados en el sistema operativo base:

| Motor | Tipo | Función | ¿Qué detecta? |
| :--- | :--- | :--- | :--- |
| **Semgrep** | **SAST** *(Código Fuente)* | Analiza la sintaxis y lógica del código (C, Python, Go, Java, JS, etc.). | Inyecciones, llamadas a funciones inseguras (`strcpy`, `sprintf`), credenciales expuestas en código, desbordamientos de memoria. |
| **Trivy** | **SCA** *(Dependencias)* | Inspecciona los archivos de dependencias (`go.mod`, `requirements.txt`, `package.json`, etc.). | CVEs públicos conocidos en librerías de terceros y entrega la versión exacta de solución. |

---

## 4. Flujo de Trabajo: ¿Qué pasa al hacer `git push` o corregir código?

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Desarrollador
    participant GL as GitLab MQuest
    participant SC as Portal SCAN-CODE
    participant DB as Base de Datos

    Dev->>GL: git push (Sube código corregido o nueva versión)
    Note over Dev,GL: La versión actualizada queda en GitLab
    
    alt Escaneo Manual Inmediato
        actor Op as Operador / Dev
        Op->>SC: Presiona "▶ Escanear" en el proyecto
    else Escaneo Automático Nocturno
        SC->>SC: Ejecución automática a las 02:00 AM
    end

    SC->>GL: Descarga el último commit vía API / Git Clone
    SC->>SC: Ejecuta Semgrep (SAST) + Trivy (SCA)
    SC->>DB: Actualiza la lista de hallazgos
    Note over SC,DB: Las vulnerabilidades resueltas se eliminan<br/>Los contadores de severidad bajan a 0
    SC-->>Dev: Dashboard actualizado con estado verde
```

### 🔄 Ciclo de Vida de una Corrección:
1. **Detección Inicial:** El portal detecta una vulnerabilidad (ej: librería `golang.org/x/net v0.2.0`).
2. **Consulta de Recomendación:** En el portal se hace clic en **`🔍 Ver Recomendación`** y se lee la sugerencia (ej: *Actualizar a versión v0.38.0*).
3. **Corrección en Código:** El desarrollador actualiza el archivo en su entorno y hace `git push` a GitLab.
4. **Validación:** Al presionar **`▶ Escanear`** (o en el escaneo nocturno), el sistema descarga la nueva versión, valida la ausencia del fallo, **elimina la alerta de la base de datos** y reduce el contador de alarmas.

---

## 5. Programación de Escaneo Automático Diario (02:00 AM)

El sistema cuenta con un demonio interno (*Background Thread Scheduler*):

- **Ruta en el Menú:** `Configuración` ➡️ `Programación Escaneo` (`/settings/schedule`).
- **Hora Predeterminada:** **`02:00` AM** todos los días.
- **Operación:** A la hora fijada, el sistema recorre secuencialmente todos los repositorios registrados, descarga la última versión y re-evalúa todas las vulnerabilidades.
- **Botón `⚡ Ejecutar Escaneo Programado Ahora`:** Permite al operador forzar un barrido global de todos los proyectos en cualquier momento.

---

## 6. Guía de Operación para el Usuario

```
├── 🏠 Resumen                -> Métricas globales y tabla de proyectos con botón de escaneo
├── 📥 Importar               -> Vinculación de nuevos proyectos desde GitLab
├── 📄 Reportes               -> Matriz general de vulnerabilidades con filtros y recomendaciones
├── 👥 Usuarios               -> Gestión de usuarios locales y autenticación LDAP
└── ⚙️ Configuración (Desplegable)
    ├── 🦊 Integraciones GitLab     -> Configuración de URL y Tokens PAT
    └── 🗓️ Programación Escaneo     -> Activar/desactivar y definir la hora del escaneo diario
```

### A. Resumen (`/`)
- Permite ver el total de proyectos y el consolidado de vulnerabilidades clasificadas en:
  - **Rojo:** Críticos / Altos
  - **Naranja:** Medios
  - **Verde:** Bajos
- Permite ejecutar escaneos individuales con **`▶ Escanear`** o ver el detalle con **`📊 Ver Reporte`**.

### B. Reportes (`/findings`)
- Permite filtrar por Proyecto, Severidad y Escáner.
- Cada fila incluye el botón **`🔍 Ver`**, que abre un modal con:
  - Regla / ID de la vulnerabilidad.
  - Archivo y número de línea.
  - Explicación del problema y solución recomendada.
  - Fragmento de código fuente afectado.

### C. Usuarios (`/users`)
- **Pestaña 1:** Creación y borrado de operadores locales.
- **Pestaña 2:** Configuración de enlace con servidor LDAP / Active Directory.

---

## 7. Mantenimiento y Comandos del Servidor

Acceso por terminal SSH:
```bash
ssh mquser@172.27.103.42
```

### Comandos de Operación:
```bash
# Estado del servicio
systemctl --user status central-scanner.service

# Reiniciar la aplicación
systemctl --user restart central-scanner.service

# Ver logs en tiempo real
journalctl --user-unit=central-scanner.service -f -n 50
```
