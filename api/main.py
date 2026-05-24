import sys
import sqlite3
from fastapi import FastAPI, HTTPException, Query,  Depends, status, Response, Header
from pydantic import BaseModel, Field, conint, validator, ValidationError
from typing import ClassVar, List, Optional
from fastapi.middleware.cors import CORSMiddleware
import re
#librerias de session
from fastapi.security import OAuth2AuthorizationCodeBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt 
from datetime import datetime, timedelta
from argon2 import PasswordHasher
#librerias acceso a api externa
import httpx
from fastapi.responses import JSONResponse

# ── AGREGADO Vanesa: librerías para integración con IA y lectura de variables de entorno ──
# json: para parsear la respuesta JSON que devuelve la IA
# os + dotenv: para leer la API Key desde el archivo .env sin hardcodearla en el código
import json
import os
from groq import Groq
from dotenv import load_dotenv
# ──────────────────────────────────────────────────────────────────────────────────────────

#configuracion para session de usuarios
SECRET_KEY = os.getenv("super_secret_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1000 * 60 * 60 * 24
#fin configuracion para session de usuarios

# ── AGREGADO Vanesa: inicialización del cliente de Groq (IA) ──────────────────────────────
# load_dotenv() lee el archivo .env y carga las variables de entorno
# GROQ_API_KEY es la clave secreta para usar la API de Groq (modelo Llama)
# groq_client es el objeto que usamos para hacer llamadas a la IA
load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
groq_client = Groq(api_key=GROQ_API_KEY)
GROQ_MODEL = "llama-3.3-70b-versatile"  # Modelo gratuito, muy bueno para análisis de código
# ──────────────────────────────────────────────────────────────────────────────────────────

#base de datos
db ="AuditCode.db"
version = f"{sys.version_info.major}.{sys.version_info.minor}"

app = FastAPI()

origins = ["*"]
# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ph = PasswordHasher()
def hash_password(password: str):
    return ph.hash(password) 

def verify_password(plain, hashed):
    try:
        ph.verify(hashed, plain)
        return True
    except:
        return False

def create_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM), expire


# Middleware de autenticación: extrae y valida el token JWT del header.
# Verifica además que la sesión esté activa en la base de datos.
# Todas las rutas protegidas usan esta función con Depends()
def get_current_user(authorization: str = Header(...)):
    try:
        token = authorization.replace("Bearer ", "")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = 1000 #payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalido")

    # conn = sqlite3.connect(db)
    # c = conn.cursor()
    # c.execute("SELECT * FROM sesiones WHERE token = ?", (token,))
    # session = c.fetchone()
    # conn.close()

    # if not session:
    #     raise HTTPException(status_code=401, detail="Sesion invalida")

    return user_id


@app.get("/")
async def read_root():
    message = f"Ejercicios Programacion de Vanguardia con FastAPI corriendo en Uvicorn con Gunicorn. Using Python {version}"
    return {"message": message}


class RegisterRequest(BaseModel):
    nombre: str
    apellido: str
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

# ── AGREGADO Vanesa: modelo de datos para el endpoint /analyze ────────────────
# Define la estructura del JSON que manda el frontend (editor Monaco)
# code: el código fuente a analizar
# language: el lenguaje seleccionado en el dropdown del editor
class AnalyzeRequest(BaseModel):
    code: str
    language: str  # python | java | kotlin | javascript | typescript | sql
# ──────────────────────────────────────────────────────────────────────────────


def init_db():
    conn = sqlite3.connect(db)
    c = conn.cursor() 
    
    c.execute('''
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT,
        apellido TEXT,
        username TEXT UNIQUE,
        password TEXT
    )
    ''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS sesiones (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        token TEXT,
        exp DATETIME
    )
    ''')

    # ?? AGREGADO Vanesa: tabla auditorias para guardar el historial por usuario ??
    # Cada analisis queda registrado con: quien lo hizo, cuando, que codigo,
    # y el resultado completo de la IA guardado como JSON en el campo 'resultado'.
    # Asi el usuario puede ver su historial y volver a consultar analisis anteriores.
    c.execute('''
              CREATE TABLE IF NOT EXISTS recordatorios
              (id INTEGER PRIMARY KEY AUTOINCREMENT,
              titulo TEXT,
              descripcion TEXT,
              fecha TEXT,
              hora TEXT)
              ''')
    
    c.execute('''
              CREATE TABLE IF NOT EXISTS reservas
              (reserva_id INTEGER PRIMARY KEY AUTOINCREMENT,
              cancha_id INTEGER,
              usuario_id INTEGER,
              horario_id DATETIME,
              descripcion TEXT,
              num_personas INTEGER)
              ''')

    # ── AGREGADO Vanesa: tabla auditorias para guardar el historial por usuario ──
    # Cada análisis queda registrado con: quién lo hizo, cuándo, qué código,
    # y el resultado completo de la IA guardado como JSON en el campo 'resultado'.
    # Así el usuario puede ver su historial y volver a consultar análisis anteriores.
    c.execute('''
        CREATE TABLE IF NOT EXISTS auditorias (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            language    TEXT NOT NULL,
            codigo      TEXT NOT NULL,
            resultado   TEXT NOT NULL,
            fecha       TEXT NOT NULL,
            hora        TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES usuarios(id)
        )
    ''')
    # ──────────────────────────────────────────────────────────────────────────────

    conn.commit()
    conn.close()  

init_db()


@app.post("/Register",status_code=status.HTTP_201_CREATED)
def register(user: RegisterRequest):
    conn = sqlite3.connect(db)
    c = conn.cursor()
    try:
        hashed = hash_password(user.password)
        c.execute("INSERT INTO usuarios (nombre, apellido, username, password) VALUES (?, ?, ?, ?)",
            (user.nombre, user.apellido, user.username, hashed))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Usuario ya existe")
    finally:
        conn.close()
    return {"msg": "Usuario creado correctamente"}
    
@app.post("/Login")
def login(data: LoginRequest):
    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute("SELECT id, password FROM usuarios WHERE username = ?", (data.username,))
    user = c.fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="Credenciales invalidas")
    user_id, hashed_password = user
    if not verify_password(data.password, hashed_password):
        raise HTTPException(status_code=401, detail="Credenciales invalidas")
    token, exp = create_token({"sub": str(user_id)})
    c.execute("INSERT INTO sesiones (user_id, token, exp) VALUES (?, ?, ?)", (user_id, token, exp))
    conn.commit()
    conn.close()
    return {"access_token": token,"token_type": "bearer","expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60}

@app.get("/me")
def me(user_id: int = Depends(get_current_user)):
    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute("SELECT id, nombre, apellido, username FROM usuarios WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return {"id": user[0],"nombre": user[1],"apellido": user[2],"username": user[3]}

@app.post("/Logout")
def logout(authorization: str = Header(...)):
    token = authorization.replace("Bearer ", "")
    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute("DELETE FROM sesiones WHERE token = ?", (token,))
    conn.commit()
    conn.close()
    return {"msg": "Sesion cerrada"}


# ??????????????????????????????????????????????????????????????????????????????
# AGREGADO Vanesa  Endpoints de Auditoria de Codigo con IA
# Rama: f-analizar
# Descripcion: recibe codigo del editor Monaco, lo analiza con Groq (Llama),
#              guarda el resultado en la tabla auditorias y expone un historial
#              por usuario identificado con id, lenguaje, fecha y hora.
# ??????????????????????????????????????????????????????????????????????????????

# ?? AGREGADO Vanesa: prompt del sistema que define el comportamiento de la IA ??
# Este texto se manda como "rol de sistema" en cada llamada a Groq.
# Le dice a la IA que actue como Senior Developer auditor y que responda
# UNICAMENTE con JSON puro, para que podamos parsearlo sin problemas.
AUDIT_SYSTEM_PROMPT = """
Sos un Senior Developer con 15 años de experiencia auditando codigo en empresas de tecnologia.
Tu tarea es analizar el fragmento de codigo que te envian e identificar problemas reales.

Categorias de severidad:
- CRITICO: vulnerabilidades de seguridad (SQL Injection, XSS, credenciales hardcodeadas, etc.)
- ADVERTENCIA: errores de logica, malas practicas, codigo que puede fallar en produccion
- SUGERENCIA: oportunidades de refactorizacion, Clean Code, naming conventions

REGLA IMPORTANTE: Responde UNICAMENTE con un objeto JSON valido.
Sin texto adicional, sin markdown, sin bloques de codigo, sin explicaciones fuera del JSON.

Estructura exacta que debe devolver:
{
  "issues": [
    {
      "severity": "CRITICO|ADVERTENCIA|SUGERENCIA",
      "type": "NOMBRE_CORTO_DEL_PROBLEMA",
      "description": "Explicacion clara del problema encontrado",
      "line": 1
    }
  ],
  "refactored_code": "El codigo completo corregido y mejorado aqui",
  "pedagogical_explanation": "Explicacion teorica del concepto fallido, escrita para un estudiante universitario de Programacion de Vanguardia"
}

Si el codigo no tiene problemas, devolve issues como [] y explica por que el codigo es correcto y seguro.
"""
# ??????????????????????????????????????????????????????????????????????????????


# ?? AGREGADO Vanesa: POST /analyze ????????????????????????????????????????????
# Endpoint principal del TP. Recibe el codigo del editor Monaco y el lenguaje.
# Flujo: valida entrada ? llama a Groq ? parsea el JSON de la IA ?
#        guarda en tabla auditorias ? devuelve el analisis completo al frontend.
# Requiere token JWT valido: el usuario debe estar logueado para poder auditar.
@app.post("/analyze", status_code=status.HTTP_200_OK)
async def analyze_code(request: AnalyzeRequest, user_id: str = Depends(get_current_user)):

    # Validar que el codigo no venga vacio
    if not request.code.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El campo 'code' no puede estar vacio."
        )

    # Validar que el lenguaje sea uno de los soportados por la plataforma
    supported_languages = ["python", "java", "kotlin", "javascript", "typescript", "sql"]
    if request.language.lower() not in supported_languages:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Lenguaje no soportado. Usa uno de: {supported_languages}"
        )

    # Construimos el mensaje para la IA: lenguaje + codigo del usuario
    user_message = f"Lenguaje: {request.language}\n\nCodigo a auditar:\n{request.code}"

    try:
        # Llamada a la API de Groq con el modelo Llama
        # temperature=0.2: valor bajo para que la IA sea precisa y consistente
        chat_completion = groq_client.chat.completions.create(
            messages=[
                {"role": "system", "content": AUDIT_SYSTEM_PROMPT},
                {"role": "user",   "content": user_message}
            ],
            model=GROQ_MODEL,
            temperature=0.2,
            max_tokens=2048,
        )
        print("Before call chat_completion")
        raw_response = chat_completion.choices[0].message.content
        print(f"After call chat_completion{str(raw_response)}") 
        
        print("RAW RESPONSE:")
        print(raw_response)

        # Extract JSON inside ``` ```
        match = re.search(r"```(?:json)?\s*(\{.*\})\s*```", raw_response, re.DOTALL)

        if match:
            json_str = match.group(1)
        else:
            json_str = raw_response.strip()        
        
        # Parseamos la respuesta de la IA de string JSON a dict de Python
        #analysis = json.loads(raw_response)
        analysis = json.loads(json_str)
  
    except json.JSONDecodeError:
        # Si la IA devolvio algo que no es JSON valido, lo controlamos con un error claro
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"El modelo de IA devolvio una respuesta invalida. Intenta de nuevo. detalle:{str(analysis)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Error al contactar el servicio de IA: {str(e)}"
        )

    # Guardamos el analisis en la tabla auditorias para el historial del usuario
    now = datetime.now()
    fecha_actual = now.strftime("%Y-%m-%d")
    hora_actual  = now.strftime("%H:%M:%S")
    # El resultado de la IA lo guardamos como string JSON en la columna 'resultado'
    resultado_json = json.dumps(analysis, ensure_ascii=False)

# Ruta para eliminar una reserva por ID
@app.delete("/reservas/{reserva_id}",status_code=status.HTTP_200_OK)
def delete_reserva(reserva_id: int):
    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute(
        "INSERT INTO auditorias (user_id, language, codigo, resultado, fecha, hora) VALUES (?, ?, ?, ?, ?, ?)",
        (int(user_id), request.language, request.code, resultado_json, fecha_actual, hora_actual)
    )
    auditoria_id = c.lastrowid
    conn.commit()
    conn.close()

    # Devolvemos el analisis completo al frontend (Monaco Editor lo muestra en el panel derecho)
    return {
        "id":                      auditoria_id,
        "language":                request.language,
        "fecha":                   fecha_actual,
        "hora":                    hora_actual,
        "issues":                  analysis.get("issues", []),
        "refactored_code":         analysis.get("refactored_code", ""),
        "pedagogical_explanation": analysis.get("pedagogical_explanation", "")
    }
# ??????????????????????????????????????????????????????????????????????????????


# ?? AGREGADO Vanesa: GET /historial ??????????????????????????????????????????
# Devuelve la lista de todas las auditorias del usuario logueado.
# Incluye: id, lenguaje, fecha, hora y un preview de los primeros 80 caracteres del codigo.
# Usado por el frontend para mostrar la tabla de historial con el modal de auditorias.
@app.get("/historial", status_code=status.HTTP_200_OK)
def get_historial(user_id: str = Depends(get_current_user)):
    conn = sqlite3.connect(db)
    c = conn.cursor()
    # ORDER BY id DESC = los mas recientes primero
    c.execute(
        "SELECT id, language, fecha, hora, codigo FROM auditorias WHERE user_id = ? ORDER BY id DESC",
        (int(user_id),)
    )
    rows = c.fetchall()
    conn.close()

    return {
        "user_id": user_id,
        "total":   len(rows),
        "historial": [
            {
                "id":             row[0],
                "language":       row[1],
                "fecha":          row[2],
                "hora":           row[3],
                # Preview de 80 caracteres para mostrar en la tabla sin cargar todo el c�digo
                "codigo_preview": row[4][:80] + "..." if len(row[4]) > 80 else row[4]
            }
            for row in rows
        ]
    }
# ??????????????????????????????????????????????????????????????????????????????


# ?? AGREGADO Vanesa: GET /historial/{auditoria_id} ???????????????????????????
# Devuelve el detalle completo de una auditoria especifica.
# El usuario hace clic en un item del historial y ve el analisis entero.
# Seguridad: la condicion AND user_id = ? impide que un usuario vea datos de otro.
@app.get("/historial/{auditoria_id}", status_code=status.HTTP_200_OK)
def get_auditoria_detalle(auditoria_id: int, user_id: str = Depends(get_current_user)):
    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute(
        "SELECT id, language, codigo, resultado, fecha, hora FROM auditorias WHERE id = ? AND user_id = ?",
        (auditoria_id, int(user_id))
    )
    row = c.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Auditoria no encontrada o no pertenece al usuario.")

    # Convertimos el string JSON guardado en DB de vuelta a dict para devolverlo estructurado
    resultado = json.loads(row[3])

    # Devolvemos el análisis completo al frontend (Monaco Editor lo muestra en el panel derecho)
    return {
        "id":                      row[0],
        "language":                row[1],
        "codigo":                  row[2],
        "fecha":                   row[4],
        "hora":                    row[5],
        "issues":                  resultado.get("issues", []),
        "refactored_code":         resultado.get("refactored_code", ""),
        "pedagogical_explanation": resultado.get("pedagogical_explanation", "")
    }
# ──────────────────────────────────────────────────────────────────────────────


# ── AGREGADO Vanesa: GET /historial ──────────────────────────────────────────
# Devuelve la lista de todas las auditorías del usuario logueado.
# Incluye: id, lenguaje, fecha, hora y un preview de los primeros 80 caracteres del código.
# Usado por el frontend para mostrar la tabla de historial con el modal de auditorías.
@app.get("/historial", status_code=status.HTTP_200_OK)
def get_historial(user_id: str = Depends(get_current_user)):
    conn = sqlite3.connect(db)
    c = conn.cursor()
    # ORDER BY id DESC = los más recientes primero
    c.execute(
        "SELECT id, language, fecha, hora, codigo FROM auditorias WHERE user_id = ? ORDER BY id DESC",
        (int(user_id),)
    )
    rows = c.fetchall()
    conn.close()

    return {
        "user_id": user_id,
        "total":   len(rows),
        "historial": [
            {
                "id":             row[0],
                "language":       row[1],
                "fecha":          row[2],
                "hora":           row[3],
                # Preview de 80 caracteres para mostrar en la tabla sin cargar todo el código
                "codigo_preview": row[4][:80] + "..." if len(row[4]) > 80 else row[4]
            }
            for row in rows
        ]
    }
# ──────────────────────────────────────────────────────────────────────────────


# ── AGREGADO Vanesa: GET /historial/{auditoria_id} ───────────────────────────
# Devuelve el detalle completo de una auditoría específica.
# El usuario hace clic en un item del historial y ve el análisis entero.
# Seguridad: la condición AND user_id = ? impide que un usuario vea datos de otro.
@app.get("/historial/{auditoria_id}", status_code=status.HTTP_200_OK)
def get_auditoria_detalle(auditoria_id: int, user_id: str = Depends(get_current_user)):
    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute(
        "SELECT id, language, codigo, resultado, fecha, hora FROM auditorias WHERE id = ? AND user_id = ?",
        (auditoria_id, int(user_id))
    )
    row = c.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Auditoría no encontrada o no pertenece al usuario.")

    # Convertimos el string JSON guardado en DB de vuelta a dict para devolverlo estructurado
    resultado = json.loads(row[3])

    return {
        "id":                      row[0],
        "language":                row[1],
        "codigo":                  row[2],
        "fecha":                   row[4],
        "hora":                    row[5],
        "issues":                  resultado.get("issues", []),
        "refactored_code":         resultado.get("refactored_code", ""),
        "pedagogical_explanation": resultado.get("pedagogical_explanation", "")
    }
# ══════════════════════════════════════════════════════════════════════════════
# FIN AGREGADO Vanesa
# ══════════════════════════════════════════════════════════════════════════════


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8181)
