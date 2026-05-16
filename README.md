# &#x20;UCI-PY-API — Plataforma de Auditoría de Código con IA

> Microservicio Python de análisis estático de código potenciado por Inteligencia Artificial.  
> Trabajo Práctico — Programación de Vanguardia 2026 | Universidad de la Ciudad de Buenos Aires

\---

## ¿Qué es este proyecto?

UCI-PY-API es el microservicio de inferencia y análisis de una plataforma de auditoría de código basada en arquitectura de microservicios. Recibe fragmentos de código fuente, los analiza utilizando un modelo de lenguaje de gran escala (LLM) y devuelve un informe estructurado con:

* 🔴 **Vulnerabilidades de seguridad** (SQL Injection, XSS, credenciales hardcodeadas, etc.)
* 🟡 **Errores de lógica y malas prácticas** de programación
* 🔵 **Sugerencias de refactorización** bajo principios de Clean Code
* 📚 **Explicación pedagógica** del concepto teórico fallido
* ✨ **Código corregido** listo para usar

A diferencia de un linter tradicional basado en reglas fijas, la plataforma utiliza un LLM que razona contextualmente sobre el código, explicando *por qué* algo está mal y cómo mejorarlo.

\---

## 

## 🏗️ Arquitectura del sistema

```
Frontend (Monaco Editor)
        │
        │ HTTP + JWT
        ▼
Backend Java (Spring Boot)  ←──  Gestión de usuarios + BD relacional
        │
        │ HTTP
        ▼
Backend Python (FastAPI)    ←──  Este repositorio
        │
        │ API Key
        ▼
Groq API (Llama 3.3 70B)   ←──  Modelo de IA open-source
```

\---

## 

## Stack tecnológico

|Componente|Tecnología|
|-|-|
|Framework API|FastAPI 0.136|
|Servidor|Uvicorn + Gunicorn|
|Modelo de IA|Llama 3.3 70B (Meta, open-source)|
|Plataforma IA|Groq API|
|Base de datos|SQLite|
|Autenticación|JWT (python-jose)|
|Hash de contraseñas|Argon2|
|Lenguaje|Python 3.10+|
|Deploy|Render|

\---

## 

## Endpoints disponibles

### Autenticación

|Método|Ruta|Descripción|
|-|-|-|
|`POST`|`/Register`|Registro de nuevo usuario|
|`POST`|`/Login`|Login — devuelve JWT token|
|`GET`|`/me`|Datos del usuario autenticado|
|`POST`|`/Logout`|Cierra la sesión activa|

### Auditoría de Código con IA 

|Método|Ruta|Descripción|
|-|-|-|
|`POST`|`/analyze`|Analiza código con IA y guarda el resultado|
|`GET`|`/historial`|Lista el historial de auditorías del usuario|
|`GET`|`/historial/{id}`|Detalle completo de una auditoría específica|

### Otros

|Método|Ruta|Descripción|
|-|-|-|
|`GET`|`/recordatorios`|CRUD de recordatorios|
|`POST`|`/reservas`|CRUD de reservas de canchas|
|`GET`|`/ejercicios/factorial/{n}`|Cálculo de factorial|
|`GET`|`/ejercicios/sumlist`|Suma recursiva de lista|

\---

## 

## Instalación y ejecución local

### 

### Requisitos previos

* Python 3.10 o superior
* API Key gratuita de [Groq](https://console.groq.com) (sin tarjeta de crédito)

### 

### Pasos



**1. Clonar el repositorio**

```bash
git clone https://github.com/mikekmaker/uci-py-api.git
cd uci-py-api
```

**2. Crear y activar entorno virtual**

```bash
python -m venv venv

# Windows
venv\\Scripts\\activate

# Mac / Linux
source venv/bin/activate
```

**3. Instalar dependencias**

```bash
cd api
pip install -r requirements.txt
```

**4. Configurar variables de entorno**

Crear un archivo `.env` dentro de la carpeta `api/`:

```
GROQ\_API\_KEY=gsk\_tu\_api\_key\_aqui
```

>  Conseguí tu API Key gratis en \[console.groq.com](https://console.groq.com) — no requiere tarjeta de crédito.

**5. Ejecutar el servidor**

```bash
uvicorn main:app --reload --port 8181
```

**6. Acceder a la documentación interactiva**

Abrí en el navegador: [http://localhost:8181/docs](http://localhost:8181/docs)

\---

## 

## Ejemplo de uso — Auditoría con IA

**Request:**

```bash
curl -X POST http://localhost:8181/analyze \\
  -H "Content-Type: application/json" \\
  -H "authorization: Bearer TU\_TOKEN\_JWT" \\
  -d '{"code": "query = SELECT \* FROM users WHERE id = + user\_input", "language": "python"}'
```

**Response:**

```json
{
  "id": 1,
  "language": "python",
  "fecha": "2026-04-29",
  "hora": "19:46:42",
  "issues": \[
    {
      "severity": "CRITICO",
      "type": "SQL\_INJECTION",
      "description": "El código concatena directamente la entrada del usuario en la query SQL.",
      "line": 1
    }
  ],
  "refactored\_code": "query = 'SELECT \* FROM users WHERE id = %s'\\ncursor.execute(query, (user\_input,))",
  "pedagogical\_explanation": "La inyección SQL ocurre cuando se concatena input del usuario directamente en una consulta..."
}
```

\---

## &#x20;

## Deploy

La API está desplegada en Render:

🔗 [**https://uci-py-api.onrender.com/docs**](https://uci-py-api.onrender.com/docs)

\---

## 

## 📁 Estructura del proyecto

```
uci-py-api/
├── api/
│   ├── main.py          # Aplicación principal FastAPI
│   ├── requirements.txt # Dependencias del proyecto
│   ├── .env.example     # Ejemplo de variables de entorno
│   └── AuditCode.db     # Base de datos SQLite (generada automáticamente)
├── README.md
└── .gitignore
```

\---

## 

## &#x20;Equipo

|Integrante|Rol|
|-|-|
|Miguel|Frontend (React + Monaco Editor)|
|Julieta|Backend Java (Spring Boot)|
|Fernando|Backend Java (Spring Boot)|
|Diego|Backend Python + README|
|Vanesa|Backend Python + Microservicio IA + README|

\---

## 

## Seguridad

* Las API Keys nunca se hardcodean en el código — se leen desde variables de entorno
* El archivo `.env` está excluido del repositorio via `.gitignore`
* Autenticación con JWT en todos los endpoints protegidos
* Control de acceso por recurso: cada usuario solo puede ver sus propias auditorías

\---

*Programación de Vanguardia 2026 — Licenciatura en Tecnologías Informáticas — Universidad de la Ciudad de Buenos Aires*

