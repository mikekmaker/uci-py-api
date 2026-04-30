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
SECRET_KEY = "super_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
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

def get_current_user(authorization: str = Header(...)):
    try:
        token = authorization.replace("Bearer ", "")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalido")

    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute("SELECT * FROM sesiones WHERE token = ?", (token,))
    session = c.fetchone()
    conn.close()

    if not session:
        raise HTTPException(status_code=401, detail="Sesion invalida")

    return user_id

def calcular_factorial(n: int) -> int:
    if n < 0:
        raise ValueError("El número no puede ser negativo")
    if n == 0 or n == 1:
        return 1
    resultado = 1
    for i in range(2, n + 1):
        resultado *= i
    return resultado

def suma_list_elems(lista, actual=0):
    if actual >= len(lista):
        return 0
    return lista[actual] + suma_list_elems(lista, actual + 1)


@app.get("/")
async def read_root():
    message = f"Ejercicios Programación de Vanguardia con FastAPI corriendo en Uvicorn con Gunicorn. Using Python {version}"
    return {"message": message}


class Recordatorio(BaseModel):
    titulo: str
    descripcion: str
    fecha: str
    hora: str
    fecha_pattern: ClassVar[re.Pattern] = re.compile(r"^\d{4}-\d{2}-\d{2}$")
    hora_pattern: ClassVar[re.Pattern] = re.compile(r"^(?:[01]\d|2[0-3]):([0-5]\d)$")

    @validator("fecha")
    def validate_fecha(cls, v):
        if not cls.fecha_pattern.match(v):
            raise ValueError("Fecha invalida. Usa el formato YYYY-MM-DD.")
        return v

    @validator("hora")
    def validate_hora(cls, v):
        if not cls.hora_pattern.match(v):
            raise ValueError("Hora invalida. Usa el formato HH:MM (24 horas).")
        return v
    
class Reserva(BaseModel):
    cancha_id: int
    usuario_id: int
    horario_id: int
    descripcion: str
    num_personas: int

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

@app.post("/recordatorios",status_code=status.HTTP_201_CREATED)
def create_recordatorio(recordatorio: Recordatorio,response:Response):
    if not recordatorio.titulo.strip():
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"detail":"titulo","msg": "El campo 'titulo' no puede estar vacio."}      
    elif not recordatorio.descripcion.strip():
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"detail":"descripcion","msg": "El campo 'descripcion' no puede estar vacio."}      
    elif not recordatorio.fecha.strip():
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"detail":"fecha","msg": "El campo 'fecha' no puede estar vacio."}      
    elif not recordatorio.hora.strip():
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"detail":"hora","msg": "El campo 'hora' no puede estar vacio."}      
     
    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute("INSERT INTO recordatorios (titulo, descripcion, fecha, hora) VALUES (?, ?, ?, ?)",
              (recordatorio.titulo, recordatorio.descripcion, recordatorio.fecha, recordatorio.hora))
    conn.commit()
    conn.close()
    recordatorio_id = c.lastrowid
    return {
            "id": recordatorio_id,
            "titulo": recordatorio.titulo,
            "descripcion": recordatorio.descripcion,
            "fecha": recordatorio.fecha,
            "hora": recordatorio.hora
    }

@app.get("/recordatorios")
async def get_recordatorios():
    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute("SELECT id, titulo, descripcion, fecha, hora FROM recordatorios")
    rows = c.fetchall()
    conn.close()
    recordatorios = [{"id": row[0], "titulo": row[1], "descripcion": row[2], "fecha": row[3], "hora": row[4]} for row in rows]
    return JSONResponse(recordatorios, status_code=status.HTTP_200_OK)

@app.put("/recordatorios/{id}",status_code=status.HTTP_200_OK)
def update_recordatorio(id: int, recordatorio: Recordatorio,response:Response):
    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute("SELECT * FROM recordatorios WHERE id = ?", (id,))
    existing_recordatorio = c.fetchone()

    if existing_recordatorio:
        if not recordatorio.titulo.strip():
            response.status_code = status.HTTP_400_BAD_REQUEST
            return {"detail":"titulo","msg": "El campo 'titulo' no puede estar vacio."}   
        elif not recordatorio.descripcion.strip():
            response.status_code = status.HTTP_400_BAD_REQUEST
            return {"detail":"descripcion","msg": "El campo 'descripcion' no puede estar vacio."}   
        elif not recordatorio.fecha.strip():
            response.status_code = status.HTTP_400_BAD_REQUEST
            return {"detail":"fecha","msg": "El campo 'fecha' no puede estar vacio."}   
        elif not recordatorio.hora.strip():
            response.status_code = status.HTTP_400_BAD_REQUEST
            return {"detail":"hora","msg": "El campo 'hora' no puede estar vacio."}   
        
        c.execute('''UPDATE recordatorios SET titulo = ?, descripcion = ?, fecha = ?, hora = ? WHERE id = ?''',
                  (recordatorio.titulo, recordatorio.descripcion, recordatorio.fecha, recordatorio.hora, id))
        conn.commit()
        conn.close()
        return {"id": id,"titulo": recordatorio.titulo,"descripcion": recordatorio.descripcion,"fecha": recordatorio.fecha,"hora": recordatorio.hora}
    else:
        conn.close()
        raise HTTPException(status_code=404, detail="Recordatorio no encontrado")

@app.delete("/recordatorios/{id}",status_code=status.HTTP_200_OK)
def delete_recordatorio(id: int):
    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute("SELECT * FROM recordatorios WHERE id = ?", (id,))
    existing_recordatorio = c.fetchone()

    if existing_recordatorio:
        c.execute("DELETE FROM recordatorios WHERE id = ?", (id,))
        conn.commit()
        conn.close()
        return {"id": id,"titulo": existing_recordatorio[1],"descripcion": existing_recordatorio[2],"fecha": existing_recordatorio[3],"hora": existing_recordatorio[4]}
    else:
        conn.close()
        raise HTTPException(status_code=404, detail="Recordatorio no encontrado")

@app.post('/reservas',status_code=status.HTTP_201_CREATED)                    
async def create_reserva(reserva: Reserva, response:Response):
    if not isinstance(reserva.cancha_id, int) or reserva.cancha_id <= 0:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"detail":"cancha","msg": "debe seleccionar una cancha valida"}
    if not isinstance(reserva.usuario_id, int) or reserva.usuario_id <= 0:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"detail":"usuario","msg": "debe seleccionar un usuario valida"}      
    elif not isinstance(reserva.horario_id, int) or reserva.horario_id <= 0:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"detail":"horario","msg": "debe seleccionar un horario valido"}      
    elif not reserva.descripcion.strip():
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"detail":"descripcion","msg": "el campo 'descripcion' no debe estar vacio"}      
    elif not isinstance(reserva.num_personas, int) or reserva.num_personas <= 0 or reserva.num_personas > 16:
        response.status_code = status.HTTP_400_BAD_REQUEST         
        return {"detail":"jugadores","msg": "debe haber al menos 1 jugador y hasta 16 jugadores"} 
    
    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute("INSERT INTO reservas (cancha_id, usuario_id, horario_id, descripcion, num_personas) VALUES (?, ?, ?, ?, ?)",
              (reserva.cancha_id, reserva.usuario_id, reserva.horario_id, reserva.descripcion, reserva.num_personas))
    reserva_id = c.lastrowid
    conn.commit()
    conn.close()
    return {"id": reserva_id,"cancha_id": reserva.cancha_id,"usuario_id": reserva.usuario_id,"horario_id": reserva.horario_id,"descripcion": reserva.descripcion,"num_personas": reserva.num_personas}

@app.get('/reservas/{reserva_id}',status_code=status.HTTP_200_OK)
async def get_reserva(reserva_id: int):
    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute("SELECT * FROM reservas WHERE reserva_id = ?", (reserva_id,))
    reserva = c.fetchone()
    conn.close()
    if reserva:
        return {"id": reserva[0],"cancha_id": reserva[1],"usuario_id": reserva[2],"horario_id": reserva[3],"descripcion": reserva[4],"num_personas": reserva[5]}
    else:
        raise HTTPException(status_code=404, detail="Reserva no encontrada")

@app.get("/reservas",status_code=status.HTTP_200_OK)
async def get_reservas():
    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute("SELECT reserva_id, cancha_id, usuario_id, horario_id, descripcion, num_personas FROM reservas")
    rows = c.fetchall()
    conn.close()
    reservas_list = [{"reserva_id": row[0], "cancha_id": row[1],"usuario_id": row[2],"horario_id": row[3],"descripcion": row[4],"num_personas": row[5]} for row in rows]
    return JSONResponse(reservas_list)
   
@app.put("/reservas/{reserva_id}",status_code=status.HTTP_200_OK)
def update_reserva(reserva_id: int, reserva: Reserva,response:Response):
    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute("SELECT * FROM reservas WHERE reserva_id = ?", (reserva_id,))
    existing_reserva = c.fetchone()
    
    if existing_reserva:
        if not isinstance(reserva.cancha_id, int) or reserva.cancha_id <= 0:
            response.status_code = status.HTTP_400_BAD_REQUEST
            return {"detail":"cancha","msg": "debe seleccionar una cancha valida"}
        elif not isinstance(reserva.usuario_id, int) or reserva.usuario_id <= 0:
            response.status_code = status.HTTP_400_BAD_REQUEST
            return {"detail":"usuario","msg": "debe seleccionar un usuario valida"}          
        elif not isinstance(reserva.horario_id, int) or reserva.horario_id <= 0:
            response.status_code = status.HTTP_400_BAD_REQUEST
            return {"detail":"horario","msg": "debe seleccionar un horario valido"}      
        elif not reserva.descripcion.strip():
            response.status_code = status.HTTP_400_BAD_REQUEST
            return {"detail":"descripcion","msg": "el campo 'descripcion' no debe estar vacio"}      
        elif not isinstance(reserva.num_personas, int) or reserva.num_personas <= 0 or reserva.num_personas > 16:
            response.status_code = status.HTTP_400_BAD_REQUEST
            return {"detail":"jugadores","msg": "debe haber al menos 1 jugador y hasta 16 jugadores"} 

        c.execute('''UPDATE reservas SET cancha_id = ?, usuario_id = ?, horario_id = ?, descripcion = ?, num_personas = ? WHERE reserva_id = ?''',
                  (reserva.cancha_id, reserva.usuario_id, reserva.horario_id, reserva.descripcion, reserva.num_personas, reserva_id))
        conn.commit()
        conn.close()
        return {"reserva_id": reserva_id,"cancha_id": reserva.cancha_id,"usuario_id": reserva.usuario_id,"horario_id": reserva.horario_id,"descripcion": reserva.descripcion,"num_personas": reserva.num_personas}
    else:
        conn.close()
        raise HTTPException(status_code=404, detail="Reserva no encontrada")

@app.delete("/reservas/{reserva_id}",status_code=status.HTTP_200_OK)
def delete_reserva(reserva_id: int):
    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute("SELECT * FROM reservas WHERE reserva_id = ?", (reserva_id,))
    existing_reserva = c.fetchone()
    if existing_reserva:
        c.execute("DELETE FROM reservas WHERE reserva_id = ?", (reserva_id,))
        conn.commit()
        conn.close()
        return {"reserva_id": reserva_id,"cancha_id": existing_reserva[1],"usuario_id": existing_reserva[2],"horario_id": existing_reserva[3],"descripcion": existing_reserva[4],"num_personas": existing_reserva[5]}
    else:
        conn.close()
        raise HTTPException(status_code=404, detail="Reserva no encontrada")
    

PREFIX = "https://db39-2800-40-16-31e-a468-6f93-336a-2045.ngrok-free.app"
HORARIOS_API_URL = "/api/horarios"
CANCHAS_API_URL = "/api/canchas"
USUARIOS_API_URL = "/api/usuarios"

@app.get("/horariosreservas/{horario_id}/reserva/{reserva_id}")
@app.get("/horariosreservas/{horario_id}")
@app.get("/horariosreservas")
async def get_horario_reserva(horario_id: Optional[int] = None, reserva_id: Optional[int] = None):
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    async with httpx.AsyncClient() as client:
        full_route = "{}{}".format(PREFIX, HORARIOS_API_URL)
        horarios_response = await client.get(full_route)
        if horarios_response.status_code == 200:
            horarios = horarios_response.json()
        else:
            raise HTTPException(status_code=404)
        
        full_route = "{}{}".format(PREFIX, CANCHAS_API_URL)
        canchas_response = await client.get(full_route)
        if canchas_response.status_code == 200:
            canchas = canchas_response.json()
        else:
            raise HTTPException(status_code=404)
        
        full_route = "{}{}".format(PREFIX, USUARIOS_API_URL)
        usuarios_response = await client.get(full_route, headers=headers)
        if usuarios_response.status_code == 200:
            usuarios = usuarios_response.json()
        else:
            raise HTTPException(status_code=404)

    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute("SELECT reserva_id, cancha_id, usuario_id, horario_id, descripcion, num_personas FROM reservas")
    reservas = c.fetchall()
    conn.close()
    reservas = [{"reserva_id":row[0], "cancha_id": row[1], "usuario_id": row[2], "horario_id": row[3], "descripcion": row[4], "num_personas": row[5]} for row in reservas]
    cancha_map = {cancha['cancha_id']: cancha for cancha in canchas}
    usuario_map = {usuario['id']: {'usuario_id': usuario['id'],'nombre': usuario['nombre'], 'apellido': usuario['apellido']} for usuario in usuarios}
    horarioreserva_array = []
    for horario in horarios:
        if horario_id is not None and horario['horario_id'] != horario_id:
            continue
        horarioreserva = {"horario_id": horario['horario_id'],"fecha": horario['fecha'],"hora": horario['hora'],"reserva": None}
        for reserva in reservas:
            if reserva_id is not None and reserva['reserva_id'] != reserva_id:
                continue
            if reserva['horario_id'] == horario['horario_id']:
                cancha = cancha_map.get(reserva['cancha_id'], {})
                usuario = usuario_map.get(reserva['usuario_id'], {})
                horarioreserva['reserva'] = {"reserva_id": reserva['reserva_id'],"descripcion": reserva['descripcion'],"num_personas": reserva['num_personas'],"cancha": cancha,"usuario": usuario}
                break
        horarioreserva_array.append(horarioreserva)
    if horario_id is not None and not horarioreserva_array:
        raise HTTPException(status_code=404, detail="Horario no encontrado")
    return JSONResponse(content=horarioreserva_array)

@app.get('/ejercicios/factorial/{num}',status_code=status.HTTP_200_OK)
async def factorial(num: int):
    try:
        resultado = calcular_factorial(num)
        return {"numero": num,"factorial": resultado}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get('/ejercicios/sumlist',status_code=status.HTTP_200_OK)
async def sumlist(lista: List[int] = Query(...)):
    try:
        resultado = suma_list_elems(lista, 0)
        return {"lista":lista,"sumados": resultado}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

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


# ══════════════════════════════════════════════════════════════════════════════
# AGREGADO Vanesa — Endpoints de Auditoría de Código con IA
# Rama: f-analizar
# Descripción: recibe código del editor Monaco, lo analiza con Groq (Llama),
#              guarda el resultado en la tabla auditorias y expone un historial
#              por usuario identificado con id, lenguaje, fecha y hora.
# ══════════════════════════════════════════════════════════════════════════════

# ── AGREGADO Vanesa: prompt del sistema que define el comportamiento de la IA ──
# Este texto se manda como "rol de sistema" en cada llamada a Groq.
# Le dice a la IA que actúe como Senior Developer auditor y que responda
# ÚNICAMENTE con JSON puro, para que podamos parsearlo sin problemas.
AUDIT_SYSTEM_PROMPT = """
Sos un Senior Developer con 15 años de experiencia auditando código en empresas de tecnología.
Tu tarea es analizar el fragmento de código que te envían e identificar problemas reales.

Categorías de severidad:
- CRITICO: vulnerabilidades de seguridad (SQL Injection, XSS, credenciales hardcodeadas, etc.)
- ADVERTENCIA: errores de lógica, malas prácticas, código que puede fallar en producción
- SUGERENCIA: oportunidades de refactorización, Clean Code, naming conventions

REGLA IMPORTANTE: Respondé ÚNICAMENTE con un objeto JSON válido.
Sin texto adicional, sin markdown, sin bloques de código, sin explicaciones fuera del JSON.

Estructura exacta que debés devolver:
{
  "issues": [
    {
      "severity": "CRITICO|ADVERTENCIA|SUGERENCIA",
      "type": "NOMBRE_CORTO_DEL_PROBLEMA",
      "description": "Explicación clara del problema encontrado",
      "line": 1
    }
  ],
  "refactored_code": "El código completo corregido y mejorado aquí",
  "pedagogical_explanation": "Explicación teórica del concepto fallido, escrita para un estudiante universitario de Programación de Vanguardia"
}

Si el código no tiene problemas, devolvé issues como [] y explicá por qué el código es correcto y seguro.
"""
# ──────────────────────────────────────────────────────────────────────────────


# ── AGREGADO Vanesa: POST /analyze ────────────────────────────────────────────
# Endpoint principal del TP. Recibe el código del editor Monaco y el lenguaje.
# Flujo: valida entrada → llama a Groq → parsea el JSON de la IA →
#        guarda en tabla auditorias → devuelve el análisis completo al frontend.
# Requiere token JWT válido: el usuario debe estar logueado para poder auditar.
@app.post("/analyze", status_code=status.HTTP_200_OK)
async def analyze_code(request: AnalyzeRequest, user_id: str = Depends(get_current_user)):

    # Validar que el código no venga vacío
    if not request.code.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El campo 'code' no puede estar vacío."
        )

    # Validar que el lenguaje sea uno de los soportados por la plataforma
    supported_languages = ["python", "java", "kotlin", "javascript", "typescript", "sql"]
    if request.language.lower() not in supported_languages:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Lenguaje no soportado. Usá uno de: {supported_languages}"
        )

    # Construimos el mensaje para la IA: lenguaje + código del usuario
    user_message = f"Lenguaje: {request.language}\n\nCódigo a auditar:\n{request.code}"

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

        raw_response = chat_completion.choices[0].message.content

        # Parseamos la respuesta de la IA de string JSON a dict de Python
        analysis = json.loads(raw_response)

    except json.JSONDecodeError:
        # Si la IA devolvió algo que no es JSON válido, lo controlamos con un error claro
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="El modelo de IA devolvió una respuesta inválida. Intentá de nuevo."
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Error al contactar el servicio de IA: {str(e)}"
        )

    # Guardamos el análisis en la tabla auditorias para el historial del usuario
    now = datetime.now()
    fecha_actual = now.strftime("%Y-%m-%d")
    hora_actual  = now.strftime("%H:%M:%S")
    # El resultado de la IA lo guardamos como string JSON en la columna 'resultado'
    resultado_json = json.dumps(analysis, ensure_ascii=False)

    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute(
        "INSERT INTO auditorias (user_id, language, codigo, resultado, fecha, hora) VALUES (?, ?, ?, ?, ?, ?)",
        (int(user_id), request.language, request.code, resultado_json, fecha_actual, hora_actual)
    )
    auditoria_id = c.lastrowid
    conn.commit()
    conn.close()

    # Devolvemos el análisis completo al frontend (Monaco Editor lo muestra en el panel derecho)
    return {
        "id":                      auditoria_id,
        "language":                request.language,
        "fecha":                   fecha_actual,
        "hora":                    hora_actual,
        "issues":                  analysis.get("issues", []),
        "refactored_code":         analysis.get("refactored_code", ""),
        "pedagogical_explanation": analysis.get("pedagogical_explanation", "")
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
