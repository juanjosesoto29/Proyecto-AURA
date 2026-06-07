"""
AURA — MVP funcional (HealthTech Innovations)
Funcionalidad crítica: gestión de proyectos + detección y rebalanceo de carga,
PROTEGIDA con autenticación y control de acceso por roles (HIPAA/GDPR).

Resuelve el requerimiento principal del caso: detectar equipos SOBRECARGADOS
(>85% de su capacidad) y SUBUTILIZADOS (<60%), y sugerir un rebalanceo de horas.

Seguridad implementada:
  - Login con contraseñas HASHEADAS (PBKDF2-HMAC-SHA256 + salt), nunca en texto plano.
  - Autenticación por token Bearer (OAuth2) con expiración de sesión (30 min).
  - Control de acceso por roles (RBAC): admin / gerente / lector (mínimo privilegio).

Stack: Python 3 + FastAPI (coherente con la Opción B — Desarrollo Iterativo).
Almacenamiento en memoria (sin BD) para mantener el MVP simple y demostrable.

Ejecutar:
    pip install -r requirements.txt
    uvicorn main:app --reload
    abrir http://127.0.0.1:8000

Usuarios de prueba:  admin/admin123 (todo) · gerente/gerente123 (asigna) · lector/lector123 (solo lectura)
"""
import hashlib
import secrets
import time
from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from pathlib import Path

app = FastAPI(title="AURA MVP — Rebalanceo de Carga", version="2.0")

# ════════════ SEGURIDAD ════════════
# Las contraseñas NUNCA se guardan en texto plano: se hashean con PBKDF2 + salt.
def _hash_pw(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 120_000).hex()

def _crear_usuario(password: str, rol: str) -> dict:
    salt = secrets.token_hex(16)
    return {"salt": salt, "hash": _hash_pw(password, salt), "rol": rol}

# Semilla de usuarios (la contraseña en texto plano se descarta tras hashear)
usuarios = {
    "admin":   _crear_usuario("admin123", "admin"),     # acceso total
    "gerente": _crear_usuario("gerente123", "gerente"), # puede asignar proyectos
    "lector":  _crear_usuario("lector123", "lector"),   # solo lectura
}

sesiones: dict = {}          # token -> {usuario, rol, exp}
DURACION_SESION = 30 * 60     # 30 minutos
oauth2 = OAuth2PasswordBearer(tokenUrl="api/login")

def usuario_actual(token: str = Depends(oauth2)) -> dict:
    s = sesiones.get(token)
    if not s:
        raise HTTPException(status_code=401, detail="Token inválido o sesión cerrada")
    if s["exp"] < time.time():
        sesiones.pop(token, None)
        raise HTTPException(status_code=401, detail="Sesión expirada, vuelva a iniciar sesión")
    return s

def requiere_rol(*roles):
    """Dependencia RBAC: solo permite a los roles indicados (mínimo privilegio)."""
    def _dep(user: dict = Depends(usuario_actual)) -> dict:
        if user["rol"] not in roles:
            raise HTTPException(status_code=403, detail="No tiene permisos para realizar esta acción")
        return user
    return _dep

# ─── Umbrales de negocio ───
UMBRAL_SOBRECARGA = 0.85   # > 85% de la capacidad => sobrecargado
UMBRAL_SUBUTILIZADO = 0.60  # < 60% de la capacidad => subutilizado

# ─── Datos en memoria (semilla: 3 sedes de HealthTech) ───
# capacidad = horas disponibles por sprint (2 semanas)
equipos = {
    "E1": {"nombre": "Backend",  "sede": "Boston", "capacidad": 320, "horas": 360},
    "E2": {"nombre": "Frontend", "sede": "Latam",  "capacidad": 320, "horas": 180},
    "E3": {"nombre": "QA",       "sede": "Latam",  "capacidad": 240, "horas": 150},
    "E4": {"nombre": "DevOps",   "sede": "Europa", "capacidad": 200, "horas": 205},
    "E5": {"nombre": "Datos",    "sede": "Europa", "capacidad": 240, "horas": 120},
}

# proyectos asignados (cada uno suma horas a un equipo)
proyectos = [
    {"nombre": "Migración historiales clínicos", "equipo": "E1", "horas": 120},
    {"nombre": "Portal pacientes Europa",        "equipo": "E4", "horas": 90},
    {"nombre": "Integración farmacia Latam",     "equipo": "E2", "horas": 80},
]


def estado_equipo(uso: float) -> str:
    if uso > UMBRAL_SOBRECARGA:
        return "SOBRECARGADO"
    if uso < UMBRAL_SUBUTILIZADO:
        return "SUBUTILIZADO"
    return "OK"


def analizar() -> dict:
    """Calcula el uso de cada equipo y sugiere rebalanceos."""
    resumen = []
    sobrecargados, subutilizados = [], []
    for eid, e in equipos.items():
        uso = e["horas"] / e["capacidad"] if e["capacidad"] else 0
        est = estado_equipo(uso)
        item = {
            "id": eid, "nombre": e["nombre"], "sede": e["sede"],
            "capacidad": e["capacidad"], "horas": e["horas"],
            "uso": round(uso * 100, 1), "estado": est,
        }
        resumen.append(item)
        if est == "SOBRECARGADO":
            sobrecargados.append(item)
        elif est == "SUBUTILIZADO":
            subutilizados.append(item)

    # sugerencias de rebalanceo: mover el exceso del sobrecargado al subutilizado con más holgura.
    # Se usa 'extra' (acumulador local) para NO alterar las horas reales mostradas en el dashboard.
    sugerencias = []
    libres = sorted(subutilizados, key=lambda x: x["uso"])  # más libre primero
    extra = {l["id"]: 0 for l in libres}                    # horas ya asignadas por sugerencias
    for s in sorted(sobrecargados, key=lambda x: -x["uso"]):
        exceso = round(s["horas"] - equipos[s["id"]]["capacidad"] * UMBRAL_SOBRECARGA)
        for libre in libres:
            cap_obj = equipos[libre["id"]]["capacidad"] * UMBRAL_SOBRECARGA
            holgura = round(cap_obj - libre["horas"] - extra[libre["id"]])
            if exceso <= 0:
                break
            if holgura <= 0:
                continue
            mover = min(exceso, holgura)
            sugerencias.append({
                "desde": s["nombre"], "hacia": libre["nombre"],
                "horas": mover,
                "detalle": f"Mover {mover}h de {s['nombre']} ({s['sede']}) a {libre['nombre']} ({libre['sede']})",
            })
            extra[libre["id"]] += mover  # efecto en cascada para la siguiente sugerencia
            exceso -= mover

    return {
        "umbrales": {"sobrecarga": UMBRAL_SOBRECARGA, "subutilizado": UMBRAL_SUBUTILIZADO},
        "equipos": resumen,
        "kpis": {
            "total_equipos": len(equipos),
            "sobrecargados": len(sobrecargados),
            "subutilizados": len(subutilizados),
            "balanceados": len([r for r in resumen if r["estado"] == "OK"]),
        },
        "sugerencias": sugerencias,
        "proyectos": proyectos,
    }


# ─── Modelos ───
class ProyectoIn(BaseModel):
    nombre: str
    equipo: str   # id de equipo (E1..E5)
    horas: int


# ─── Endpoints ───
@app.get("/", response_class=HTMLResponse)
def home():
    """Página pública: pantalla de login + dashboard."""
    return (Path(__file__).parent / "index.html").read_text(encoding="utf-8")


@app.post("/api/login")
def login(form: OAuth2PasswordRequestForm = Depends()):
    """Valida credenciales contra el hash almacenado y entrega un token de sesión."""
    u = usuarios.get(form.username)
    if not u or _hash_pw(form.password, u["salt"]) != u["hash"]:
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")
    token = secrets.token_urlsafe(24)
    sesiones[token] = {"usuario": form.username, "rol": u["rol"], "exp": time.time() + DURACION_SESION}
    return {"access_token": token, "token_type": "bearer", "rol": u["rol"], "usuario": form.username}


@app.post("/api/logout")
def logout(token: str = Depends(oauth2)):
    sesiones.pop(token, None)
    return {"ok": True}


@app.get("/api/analisis")
def api_analisis(user: dict = Depends(usuario_actual)):
    """[Autenticado] Análisis de carga y sugerencias de rebalanceo."""
    return analizar()


@app.get("/api/equipos")
def api_equipos(user: dict = Depends(usuario_actual)):
    """[Autenticado] Lista de equipos."""
    return equipos


@app.post("/api/proyectos")
def api_add_proyecto(p: ProyectoIn, user: dict = Depends(requiere_rol("admin", "gerente"))):
    """[admin/gerente] Crea un proyecto y recalcula la carga. El rol 'lector' no puede."""
    if p.equipo not in equipos:
        raise HTTPException(status_code=404, detail="Equipo no existe")
    if p.horas <= 0:
        raise HTTPException(status_code=400, detail="Las horas deben ser > 0")
    proyectos.append({"nombre": p.nombre, "equipo": p.equipo, "horas": p.horas})
    equipos[p.equipo]["horas"] += p.horas
    return analizar()
