# uci-py-api
API python para tp de la universidad de la ciudad

1. OBJETIVO ARQUITECTÓNICO
Este microservicio Python tiene como responsabilidad central realizar el procesamiento inteligente de auditoría de código fuente recibido desde el BFF Orquestador Java, delegando el análisis especializado a un motor externo de IA denominado IAEngine.
Su propósito NO es persistir información ni gestionar autenticación de usuarios, sino actuar como un servicio especializado de análisis, normalización y enriquecimiento de resultados técnicos.
Se define como un microservicio stateless, desacoplado y orientado a integración síncrona HTTP.
? PRINCIPIO ARQUITECTÓNICO CLAVE
Este servicio NO maneja estado, NO persiste datos y NO gestiona usuarios.
Es una capa de procesamiento puro entre el orquestador y el motor IA.

2. RESPONSABILIDAD GENERAL DEL SERVICIO
Atributo	Valor
Nombre del Servicio	Code Review AI Service
Endpoint Principal	POST /analyze
Responsabilidad Principal	Recibir código desde Java, enviarlo al motor IA, procesar respuesta y retornar JSON normalizado con hallazgos clasificados por severidad

3. DISEÑO POR CAPAS
El servicio Python sigue una arquitectura en capas clara y desacoplada:





3.1 Controller Layer
Componente: CodeReviewController
Responsabilidades:
    • Exponer endpoint REST /analyze
    • Validar request de entrada y metadata obligatoria
    • Gestionar errores de capa superior
    • Delegar lógica a PythonIAService
    • Retornar respuesta normalizada
    • Agregar trazabilidad (correlation-id)
3.2 Service Layer
Componente: PythonIAService
Responsabilidades:
    • Orquestar el flujo de análisis
    • Aplicar reglas de negocio
    • Invocar IAEngineClient
    • Normalizar respuesta externa
    • Clasificar severidad y estandarizar findings
    • Gestionar errores funcionales
    • Aplicar retry controlado
3.3 Integration Layer
Componente: IAEngineClient
Responsabilidades:
    • Comunicación HTTP con IAEngine
    • Serialización/deserialización
    • Manejo de timeout
    • Retry técnico
    • Circuit breaker
    • Gestión de headers técnicos
    • Seguridad de integración

3.4 DTO Layer
Componentes:
DTO	Propósito
AnalyzeCodeRequest	Request de entrada
AnalyzeCodeResponse	Response normalizada
FindingDTO	Hallazgo individual
ErrorResponse	Response de error
3.5 Domain Model Layer
Componentes:
Modelo	Propósito
ReviewResult	Resultado completo del análisis
SecurityFinding	Hallazgo de seguridad
SeverityLevel	Nivel de severidad
Recommendation	Recomendación técnica
TechnicalRisk	Riesgo técnico identificado

4. ENDPOINT REST
POST /analyze
Headers Requeridos:
Header	Valor
Authorization	Bearer <internal-token>
X-Correlation-Id	UUID
X-Request-Source	JAVA-BFF

5. EJEMPLO DE REQUEST
{
  "language": "java",
  "code": "public class PaymentProcessor {...}"
  "analysis_type": "FullReview"
}

6. EJEMPLO DE RESPONSE
{
  "id": 1,
  "language": "java",
  "fecha": "2026-05-01",
  "hora": "21:05:19",
  "issues": [
    {
      "severity": "CRITICO",
      "type": "SQL_INJECTION",
      "description": "Aunque se utiliza PreparedStatement...",
      "line": 15
    },
    {
      "severity": "ADVERTENCIA",
      "type": "MANEJO_DE_EXCEPCIONES",
      "description": "El código no maneja adecuadamente...",
      "line": 10
    },
    {
      "severity": "SUGERENCIA",
      "type": "NOMBRE_DE_VARIABLES",
      "description": "Los nombres de variables...",
      "line": 5
    }
  ],
  "refactored_code": "public class LoginSeguro { ... }",
  "pedagogical_explanation": "La seguridad en autenticación..."
}

7. MANEJO DE ERRORES
Código HTTP	Descripción
400	Bad Request - Request inválido o falta información requerida
401	Unauthorized - Token inválido o ausente
503	Service Unavailable - Motor IA no disponible
500	Internal Server Error - Error inesperado del servidor

8. RESILIENCIA
Mecanismo	Configuración
Timeout	Timeout estricto: 3s a 8s máximo
Retry	Retry controlado solo para 502/503/504
Circuit Breaker	Circuit Breaker recomendado para protección
Fallback	Fallback controlado si el negocio lo permite

9. SEGURIDAD
    • Bearer Token interno: Autenticación mediante token compartido entre servicios
    • mTLS + JWT interno firmado: Opción robusta para comunicación inter-servicios
    • Whitelist de origen: Solo aceptar requests desde fuentes autorizadas
    • Rate limiting interno: Protección contra sobrecarga de requests
    • Payload size limit: Límite en el tamaño de código enviado para análisis
10. OBSERVABILIDAD
    • Logging estructurado JSON: Logs en formato JSON para fácil indexación
    • OnRender Metrics: Métricas de rendimiento y uso
    • OpenTelemetry Tracing: Trazabilidad distribuida de requests
11. ESCALABILIDAD
    • Stateless: Sin estado compartido entre instancias
    • Docker opcional: Contenedorización para portabilidad
    • Kubernetes friendly: Diseñado para orquestación en K8s
    • Async HTTP Client recomendado: httpx para operaciones no bloqueantes

12. RECOMENDACIONES TÉCNICAS
Framework recomendado: FastAPI
Librerías sugeridas:
Librería	Propósito
FastAPI	Framework web moderno y rápido
Pydantic	Validación de datos y DTOs
httpx	Cliente HTTP asíncrono
tenacity	Retry y resiliencia
structlog	Logging estructurado
prometheus-client	Métricas de OnRender
OpenTelemetry	Tracing distribuido
uvicorn	Servidor ASGI
gunicorn	Process manager para producción

13. ESTRUCTURA 
app/
??? api/controllers/
??? services/
??? clients/
??? dto/
??? domain/
??? core/
??? observability/
??? tests/
??? main.py
??? requirements.txt

14. CONCLUSIÓN
Este servicio Python debe mantenerse pequeño, especializado, stateless y altamente observable.
Su responsabilidad principal es ser una capa robusta y confiable entre el orquestador Java y el motor externo de IA.
Principios arquitectónicos clave:
    • Separación de responsabilidades: Controller, Service, Integration claramente definidos
    • Resiliencia: Timeout, retry y circuit breaker configurados
    • Seguridad: Autenticación robusta entre servicios
    • Observabilidad: Logging, métricas y tracing completos
    • Escalabilidad: Diseño stateless preparado para orquestación
RECORDATORIO FINAL
Este microservicio NO persiste información
NO gestiona usuarios
NO mantiene estado
Es una capa de procesamiento especializado en análisis de código
